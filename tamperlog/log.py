"""The append-only log file: one canonical JSON entry per line.

Appends and checkpoints take an exclusive lock on the log file, so several processes can use the same log
safely. Each is fsynced before it returns, and the containing directory is fsynced when a file was just
created; that is as durable as the filesystem's fsync is. Before appending, the writer checks the LAST entry only
(its hash and its signature); it does not re-verify the whole file, so run ``verify`` regularly and keep
checkpoints elsewhere.
"""

from __future__ import annotations

import fcntl
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import CanonicalError, canonical_json, parse_canonical
from .checkpoint import Checkpoint, checkpoint_from_dict, make_checkpoint
from .entry import (
    GENESIS_PREV,
    Entry,
    check_log_id,
    compute_hash,
    entry_from_dict,
    format_time,
    make_entry,
    parse_time,
    signing_message,
)
from .keys import verify_signature


class LogError(Exception):
    """The log file cannot be read or extended."""


def parse_entry_line(line: bytes) -> Entry:
    """Parses one stored line (without its newline); the line must be exactly canonical."""
    try:
        return entry_from_dict(parse_canonical(line))
    except (CanonicalError, ValueError) as err:
        raise LogError(str(err)) from err


def read_entries(path: Path) -> list[Entry]:
    """Reads every entry, strictly. Raises LogError naming the first bad line. Does NOT verify hashes or signatures."""
    return parse_entries(path.read_bytes())


def parse_entries(data: bytes) -> list[Entry]:
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise LogError("the log ends in the middle of an entry (no final newline)")
    entries = []
    for number, line in enumerate(data[:-1].split(b"\n"), start=1):
        try:
            entries.append(parse_entry_line(line))
        except LogError as err:
            raise LogError(f"line {number}: {err}") from err
    return entries


def read_checkpoints(path: Path) -> list[Checkpoint]:
    if not path.exists():
        return []
    data = path.read_bytes()
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise LogError("the checkpoint file ends in the middle of a line")
    out = []
    for number, line in enumerate(data[:-1].split(b"\n"), start=1):
        try:
            out.append(checkpoint_from_dict(parse_canonical(line)))
        except (CanonicalError, ValueError) as err:
            raise LogError(f"checkpoint line {number}: {err}") from err
    return out


def _fsync_directory(path: Path) -> None:
    """Makes a newly created file's directory entry durable (a power cut could otherwise lose the file)."""
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def checkpoint_path(log_path: Path) -> Path:
    return log_path.with_name(log_path.name + ".checkpoints")


def _last_line(handle: BinaryIO) -> bytes | None:
    """The last complete line of an open file, found by reading backwards from the end."""
    size = handle.seek(0, os.SEEK_END)
    if size == 0:
        return None
    handle.seek(size - 1)
    if handle.read(1) != b"\n":
        raise LogError(
            "the file ends in the middle of an entry (or line); repair it with `tamperlog repair` before appending"
        )
    chunk, end, buf = 8192, size - 1, b""
    pos = end
    while pos > 0:
        step = min(chunk, pos)
        pos -= step
        handle.seek(pos)
        buf = handle.read(step) + buf
        newline = buf.rfind(b"\n")
        if newline != -1:
            return buf[newline + 1 :]
    return buf


class LogWriter:
    def __init__(
        self, path: Path, key: Ed25519PrivateKey, log_id: str, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.path = path
        self.key = key
        self.log_id = check_log_id(log_id)
        self.clock = clock or (lambda: datetime.now(UTC))

    def append(self, payload: Any) -> Entry:
        """Adds one entry holding ``payload``; returns it once it is on disk."""
        canonical_json(payload)  # refuse an unencodable payload before touching the file
        created = not self.path.exists()
        with open(self.path, "a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                tail = _last_line(handle)
                if tail is None:
                    seq, prev, last_time = 0, GENESIS_PREV, None
                else:
                    last = parse_entry_line(tail)
                    self._check_tail(last)
                    seq, prev, last_time = last.seq + 1, last.hash, last.time
                now = format_time(self.clock())
                if last_time is not None and parse_time(now) < parse_time(last_time):
                    raise LogError(f"the clock ({now}) is earlier than the last entry ({last_time}); not appending")
                entry = make_entry(self.log_id, seq, now, payload, prev, self.key)
                handle.seek(0, os.SEEK_END)
                handle.write(entry.line())
                handle.flush()
                os.fsync(handle.fileno())
                if created:
                    _fsync_directory(self.path)
                return entry
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _check_tail(self, last: Entry) -> None:
        """Refuses to chain onto a last entry that does not hash correctly or was not signed by this key."""
        if compute_hash(self.log_id, last.seq, last.time, last.payload, last.prev).hex() != last.hash:
            raise LogError("the last entry's hash does not match its content; the log is damaged")
        if not verify_signature(self.key.public_key(), bytes.fromhex(last.sig), signing_message(last.hash_bytes())):
            raise LogError("the last entry was not signed by this key")

    def checkpoint(self) -> Checkpoint:
        """Signs the current size and Merkle root, and appends the checkpoint to the checkpoint file.

        The log lock is held from reading the entries until the checkpoint is on disk, so no append can slip in
        between, and checkpoints are written in the order of the sizes they describe. A checkpoint is refused if
        the checkpoint file ends in a half-written line, or if the clock is earlier than the last checkpoint.
        """
        log_created = not self.path.exists()
        cp_file = checkpoint_path(self.path)
        cp_created = not cp_file.exists()
        with open(self.path, "a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                handle.seek(0)
                entries = parse_entries(handle.read())
                now = format_time(self.clock())
                with open(cp_file, "a+b") as out:
                    last = _last_line(out)  # refuses a file that ends in a half-written line
                    if last is not None:
                        try:
                            previous = checkpoint_from_dict(parse_canonical(last))
                        except (CanonicalError, ValueError) as err:
                            raise LogError(f"the last checkpoint is unreadable: {err}") from err
                        if parse_time(now) < parse_time(previous.time):
                            raise LogError(f"the clock ({now}) is earlier than the last checkpoint ({previous.time})")
                    cp = make_checkpoint(self.log_id, entries, self.key, now)
                    out.seek(0, os.SEEK_END)
                    out.write(cp.line())
                    out.flush()
                    os.fsync(out.fileno())
                if log_created:
                    _fsync_directory(self.path)
                if cp_created:
                    _fsync_directory(cp_file)
                return cp
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def repair_tail(path: Path) -> int:
    """Cuts a partial last entry (a crash during a write) off the end. Returns how many bytes were removed."""
    with open(path, "r+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        data = handle.read()
        keep = data.rfind(b"\n") + 1
        removed = len(data) - keep
        if removed:
            handle.truncate(keep)
            handle.flush()
            os.fsync(handle.fileno())
        return removed
