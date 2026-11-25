from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from tamperlog.checkpoint import Checkpoint
from tamperlog.entry import GENESIS_PREV, Entry, format_time, make_entry
from tamperlog.log import LogWriter, read_checkpoints, read_entries


class Clock:
    """A clock that advances one second per reading, so entry times are distinct and predictable."""

    def __init__(self, start: str = "2026-01-01T00:00:00Z") -> None:
        self.now = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


@dataclass
class Fixture:
    log_id: str
    path: Path
    cp_path: Path
    key: Ed25519PrivateKey
    pub: Ed25519PublicKey
    clock: Clock

    def writer(self) -> LogWriter:
        return LogWriter(self.path, self.key, self.log_id, self.clock)

    def entries(self) -> list[Entry]:
        return read_entries(self.path)

    def checkpoints(self) -> list[Checkpoint]:
        return read_checkpoints(self.cp_path)

    def lines(self) -> list[bytes]:
        return self.path.read_bytes().splitlines(keepends=True)


def build(
    tmp_path: Path, count: int = 10, checkpoint_at: tuple[int, ...] = (4, 10), log_id: str = "audit-test"
) -> Fixture:
    """A signed log of ``count`` entries with checkpoints taken after the given sizes."""
    key = Ed25519PrivateKey.generate()
    fx = Fixture(log_id, tmp_path / "log.jsonl", tmp_path / "log.jsonl.checkpoints", key, key.public_key(), Clock())
    writer = fx.writer()
    for i in range(count):
        writer.append({"event": "step", "n": i})
        if i + 1 in checkpoint_at:
            writer.checkpoint()
    return fx


def rechain(
    log_id: str, entries: list[Entry], start: int, key: Ed25519PrivateKey, edits: dict[int, Any] | None = None
) -> list[Entry]:
    """Rebuilds entries[start:] as a valid chain signed with ``key`` (what an attacker who holds a key can do).

    ``edits`` maps an entry number to a replacement payload.
    """
    out = list(entries[:start])
    prev = out[-1].hash if out else GENESIS_PREV
    for e in entries[start:]:
        payload = (edits or {}).get(e.seq, e.payload)
        made = make_entry(log_id, e.seq, e.time, payload, prev, key)
        out.append(made)
        prev = made.hash
    return out


def to_bytes(entries: list[Entry]) -> bytes:
    return b"".join(e.line() for e in entries)


def time_plus(base: str, seconds: int) -> str:
    return format_time(datetime.strptime(base, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC) + timedelta(seconds=seconds))
