"""The offline verifier. It needs only the log file, the writer's PUBLIC key, and (optionally) checkpoints.

It re-derives everything from the bytes: nothing the file claims about itself is trusted. Findings carry a
stable code, so callers (and tests) can tell a forged signature from a broken chain from a truncation.

What a passing result means: the entries were written, in this order and without change, by the holder of the
public key you supplied, for the log id you supplied, and (if you supplied trusted checkpoints) the log has
not been cut back or rewritten before them. It does not mean the times are true, or that nothing newer than
your latest trusted checkpoint was altered by someone holding the signing key.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import merkle
from .canonical import CanonicalError, parse_canonical
from .checkpoint import Checkpoint, leaf_hashes, verify_checkpoint_signature
from .entry import GENESIS_PREV, Entry, compute_hash, entry_from_dict, parse_time, signing_message
from .keys import verify_signature

# Finding codes
BAD_FORMAT = "BAD_FORMAT"  # not valid canonical JSON, wrong shape, or bad framing
BAD_SEQ = "BAD_SEQ"  # entry numbers are not 0, 1, 2, ...
BAD_PREV = "BAD_PREV"  # an entry does not point at the hash of the entry before it
BAD_HASH = "BAD_HASH"  # an entry's hash does not match its content
BAD_SIGNATURE = "BAD_SIGNATURE"  # an entry was not signed by the expected key
BAD_TIME_ORDER = "BAD_TIME_ORDER"  # time runs backwards
CP_BAD_SIGNATURE = "CHECKPOINT_BAD_SIGNATURE"
CP_BEYOND_LOG = "CHECKPOINT_BEYOND_LOG"  # the log is shorter than a checkpoint says it was: truncated
CP_ROOT_MISMATCH = "CHECKPOINT_ROOT_MISMATCH"  # the log's early entries no longer match a checkpoint: rewritten
CP_ORDER = "CHECKPOINT_ORDER"  # checkpoints shrink or go back in time


@dataclass(frozen=True)
class Finding:
    code: str
    seq: int | None  # the entry (or checkpoint position) concerned
    detail: str


@dataclass
class Report:
    ok: bool = True
    entries: int = 0
    checkpoints_checked: int = 0
    head: str = GENESIS_PREV  # the hash of the last entry, as read
    findings: list[Finding] = field(default_factory=list)

    def add(self, code: str, seq: int | None, detail: str) -> None:
        self.ok = False
        self.findings.append(Finding(code, seq, detail))


def _parse(data: bytes, report: Report) -> list[Entry]:
    entries: list[Entry] = []
    if not data:
        return entries
    if not data.endswith(b"\n"):
        report.add(BAD_FORMAT, None, "the file ends in the middle of an entry (no final newline)")
    lines = data.split(b"\n")
    if data.endswith(b"\n"):
        lines.pop()
    else:
        lines = lines[:-1]  # the partial last line is not an entry
    for index, line in enumerate(lines):
        try:
            entries.append(entry_from_dict(parse_canonical(line)))
        except (CanonicalError, ValueError) as err:
            report.add(BAD_FORMAT, index, f"line {index + 1}: {err}")
            return entries  # without a readable entry, later lines cannot be tied to it
    return entries


def verify_log(
    data: bytes,
    public_key: Ed25519PublicKey,
    log_id: str,
    checkpoints: Sequence[Checkpoint] = (),
    *,
    max_findings: int = 50,
) -> Report:
    """Verifies log bytes against a public key and optional checkpoints.

    ``max_findings`` only caps how many findings are collected (at least one); it never skips checking.
    """
    if max_findings < 1:
        raise ValueError("max_findings must be at least 1")
    report = Report()
    entries = _parse(data, report)
    report.entries = len(entries)
    previous_time = None
    for i, e in enumerate(entries):
        if len(report.findings) >= max_findings:
            break
        if e.seq != i:
            report.add(BAD_SEQ, i, f"entry {i} says it is number {e.seq}")
        expected_prev = entries[i - 1].hash if i else GENESIS_PREV
        if e.prev != expected_prev:
            report.add(BAD_PREV, i, "does not point at the hash of the entry before it")
        if compute_hash(log_id, e.seq, e.time, e.payload, e.prev).hex() != e.hash:
            report.add(BAD_HASH, i, "the entry's hash does not match its content")
        elif not verify_signature(public_key, bytes.fromhex(e.sig), signing_message(e.hash_bytes())):
            report.add(BAD_SIGNATURE, i, "not signed by the expected key")
        moment = parse_time(e.time)
        if previous_time is not None and moment < previous_time:
            report.add(BAD_TIME_ORDER, i, f"{e.time} is earlier than the entry before it")
        previous_time = moment
    if entries:
        report.head = entries[-1].hash
    _verify_checkpoints(entries, public_key, log_id, checkpoints, report)
    return report


def _verify_checkpoints(
    entries: Sequence[Entry],
    public_key: Ed25519PublicKey,
    log_id: str,
    checkpoints: Sequence[Checkpoint],
    report: Report,
) -> None:
    leaves = leaf_hashes(entries)
    last: Checkpoint | None = None
    for n, cp in enumerate(checkpoints):
        report.checkpoints_checked += 1
        if not verify_checkpoint_signature(log_id, cp, public_key):
            report.add(CP_BAD_SIGNATURE, n, f"checkpoint {n} was not signed by the expected key")
            continue
        if last is not None and (cp.size < last.size or parse_time(cp.time) < parse_time(last.time)):
            report.add(CP_ORDER, n, f"checkpoint {n} is smaller or older than the one before it")
        last = cp
        if cp.size > len(entries):
            report.add(CP_BEYOND_LOG, n, f"checkpoint {n} covers {cp.size} entries but the log has {len(entries)}")
            continue
        if merkle.root(leaves[: cp.size]).hex() != cp.root:
            report.add(CP_ROOT_MISMATCH, n, f"the first {cp.size} entries no longer match checkpoint {n}")
