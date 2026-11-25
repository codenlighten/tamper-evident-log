"""What an entry is, how it is hashed, and how it is signed.

An entry commits to the log it belongs to (``log_id``), its position (``seq``), its time, its payload and
the hash of the entry before it (``prev``). Its hash covers all of them, so changing, removing or reordering
anything earlier changes every later hash. The log id is not stored in each line: the verifier supplies the
id it expects, so entries copied from another log (even one signed by the same key) fail to verify. The
signature covers the hash, so only the holder of the key can produce an entry that verifies. Hashes and
signatures are domain-separated: an entry hash can never be mistaken for a checkpoint, nor a signature over
one for a signature over the other.

The time in an entry is whatever the writer's clock said. It is signed, but it is not independent evidence
of when something happened.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_json

GENESIS_PREV = "0" * 64
ENTRY_HASH_DOMAIN = b"tamperlog-entry-v1\x00"
ENTRY_SIG_DOMAIN = b"tamperlog-entry-sig-v1\x00"
ENTRY_FIELDS = frozenset({"seq", "time", "payload", "prev", "hash", "sig"})
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")


@dataclass(frozen=True)
class Entry:
    seq: int
    time: str
    payload: Any
    prev: str
    hash: str
    sig: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "time": self.time,
            "payload": self.payload,
            "prev": self.prev,
            "hash": self.hash,
            "sig": self.sig,
        }

    def line(self) -> bytes:
        """The exact bytes stored for this entry: canonical JSON and a newline."""
        return canonical_json(self.as_dict()) + b"\n"

    def hash_bytes(self) -> bytes:
        return bytes.fromhex(self.hash)


def format_time(moment: datetime) -> str:
    """RFC 3339 UTC to the second, the only time format entries may use."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text: str) -> datetime:
    if not _TIME.match(text):
        raise ValueError(f"time {text!r} is not YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def check_log_id(log_id: str) -> str:
    """A log id is a short, non-empty name without control characters; it is part of what gets signed."""
    if (
        not isinstance(log_id, str)
        or not 1 <= len(log_id) <= 128
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in log_id)
    ):
        raise ValueError("a log id must be 1 to 128 characters with no control characters")
    return log_id


def compute_hash(log_id: str, seq: int, time: str, payload: Any, prev: str) -> bytes:
    body = canonical_json({"log": check_log_id(log_id), "seq": seq, "time": time, "payload": payload, "prev": prev})
    return hashlib.sha256(ENTRY_HASH_DOMAIN + body).digest()


def signing_message(entry_hash: bytes) -> bytes:
    return ENTRY_SIG_DOMAIN + entry_hash


def make_entry(log_id: str, seq: int, time: str, payload: Any, prev: str, key: Ed25519PrivateKey) -> Entry:
    parse_time(time)
    digest = compute_hash(log_id, seq, time, payload, prev)
    signature = key.sign(signing_message(digest))
    return Entry(seq=seq, time=time, payload=payload, prev=prev, hash=digest.hex(), sig=signature.hex())


def entry_from_dict(raw: Any) -> Entry:
    """Builds an Entry from parsed JSON, checking the shape strictly (no missing, extra or mistyped fields)."""
    if not isinstance(raw, dict) or set(raw) != ENTRY_FIELDS:
        raise ValueError("an entry must be an object with exactly: " + ", ".join(sorted(ENTRY_FIELDS)))
    seq, time, prev, digest, sig = raw["seq"], raw["time"], raw["prev"], raw["hash"], raw["sig"]
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative integer")
    if not isinstance(time, str) or not _TIME.match(time):
        raise ValueError("time must look like 2026-01-31T12:00:00Z")
    parse_time(time)  # rejects a well-formed but impossible date such as 2026-13-45
    if not isinstance(prev, str) or not _HEX64.match(prev):
        raise ValueError("prev must be 64 lowercase hex characters")
    if not isinstance(digest, str) or not _HEX64.match(digest):
        raise ValueError("hash must be 64 lowercase hex characters")
    if not isinstance(sig, str) or not _HEX128.match(sig):
        raise ValueError("sig must be 128 lowercase hex characters")
    canonical_json(raw["payload"])  # a payload that cannot be encoded can never have been hashed: refuse it here
    return Entry(seq=seq, time=time, payload=raw["payload"], prev=prev, hash=digest, sig=sig)
