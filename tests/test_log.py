from __future__ import annotations

import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tamperlog.canonical import CanonicalError
from tamperlog.entry import GENESIS_PREV
from tamperlog.keys import generate
from tamperlog.log import LogError, LogWriter, read_entries, repair_tail
from tamperlog.verify import verify_log

from .helpers import Clock, build


def test_entries_are_numbered_chained_and_verify(tmp_path: Path) -> None:
    fx = build(tmp_path, 6, checkpoint_at=())
    entries = fx.entries()
    assert [e.seq for e in entries] == list(range(6))
    assert entries[0].prev == GENESIS_PREV
    assert all(entries[i].prev == entries[i - 1].hash for i in range(1, 6))
    assert verify_log(fx.path.read_bytes(), fx.pub, fx.log_id).ok


def test_every_line_is_the_exact_canonical_encoding_of_its_entry(tmp_path: Path) -> None:
    fx = build(tmp_path, 3, checkpoint_at=())
    assert fx.path.read_bytes() == b"".join(e.line() for e in fx.entries())


def test_an_empty_log_verifies_and_has_no_entries(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    assert read_entries(path) == []
    assert verify_log(b"", Ed25519PrivateKey.generate().public_key(), "x").ok


def test_an_unencodable_payload_is_refused_and_the_file_is_untouched(tmp_path: Path) -> None:
    fx = build(tmp_path, 2, checkpoint_at=())
    before = fx.path.read_bytes()
    for bad in (1.5, {"x": float("nan")}, {1: 2}, "\ud800"):
        with pytest.raises(CanonicalError):
            fx.writer().append(bad)
    assert fx.path.read_bytes() == before


def test_the_clock_going_backwards_is_refused_not_hidden(tmp_path: Path) -> None:
    fx = build(tmp_path, 2, checkpoint_at=())
    early = Clock("2020-01-01T00:00:00Z")
    with pytest.raises(LogError, match="earlier than the last entry"):
        LogWriter(fx.path, fx.key, fx.log_id, early).append({"late": True})
    assert len(fx.entries()) == 2


def test_the_writer_will_not_chain_onto_a_tail_signed_by_another_key(tmp_path: Path) -> None:
    fx = build(tmp_path, 2, checkpoint_at=())
    other = LogWriter(fx.path, Ed25519PrivateKey.generate(), fx.log_id, fx.clock)
    with pytest.raises(LogError, match="not signed by this key"):
        other.append({"x": 1})


def test_the_writer_will_not_chain_onto_a_damaged_tail(tmp_path: Path) -> None:
    fx = build(tmp_path, 2, checkpoint_at=())
    data = fx.path.read_bytes().replace(b'"n":1', b'"n":9')
    fx.path.write_bytes(data)
    with pytest.raises(LogError, match="damaged"):
        fx.writer().append({"x": 1})


def test_a_crash_mid_write_leaves_a_partial_line_that_blocks_appends_until_repaired(tmp_path: Path) -> None:
    fx = build(tmp_path, 3, checkpoint_at=())
    good = fx.path.read_bytes()
    fx.path.write_bytes(good + b'{"seq":3,"time":"2026-01-01T0')  # the process died part-way through a write
    with pytest.raises(LogError, match="middle of an entry"):
        fx.writer().append({"x": 1})
    assert not verify_log(fx.path.read_bytes(), fx.pub, fx.log_id).ok  # and the verifier notices too
    assert repair_tail(fx.path) == len(b'{"seq":3,"time":"2026-01-01T0')
    assert fx.path.read_bytes() == good
    assert verify_log(fx.path.read_bytes(), fx.pub, fx.log_id).ok
    fx.writer().append({"x": 1})
    assert len(fx.entries()) == 4
    assert repair_tail(fx.path) == 0  # nothing to repair on a healthy log


def test_concurrent_appenders_in_one_process_never_corrupt_the_log(tmp_path: Path) -> None:
    fx = build(tmp_path, 0, checkpoint_at=())

    def work(worker: int) -> None:
        w = LogWriter(
            fx.path, fx.key, fx.log_id, lambda: fx.clock.now + timedelta(0)
        )  # a steady clock: equal times are allowed
        for i in range(25):
            w.append({"worker": worker, "i": i})

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(work, range(8)))
    entries = fx.entries()
    assert len(entries) == 200
    assert verify_log(fx.path.read_bytes(), fx.pub, fx.log_id).ok
    assert sorted((e.payload["worker"], e.payload["i"]) for e in entries) == [
        (w, i) for w in range(8) for i in range(25)
    ]


def test_concurrent_appenders_in_separate_processes_never_corrupt_the_log(tmp_path: Path) -> None:
    priv, pub = tmp_path / "k.key", tmp_path / "k.pub"
    generate(priv, pub)
    log = tmp_path / "multi.jsonl"
    procs = [
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "tamperlog",
                "append",
                "--log",
                str(log),
                "--key",
                str(priv),
                "--log-id",
                "multi",
                "--payload",
                f'{{"p":{p}}}',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        for p in range(12)
    ]
    for proc in procs:
        _, err = proc.communicate(timeout=60)
        assert proc.returncode == 0, err.decode()
    result = subprocess.run(
        [sys.executable, "-m", "tamperlog", "verify", "--log", str(log), "--pubkey", str(pub), "--log-id", "multi"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout
    assert "12 entries" in result.stdout
    assert sorted(e.payload["p"] for e in read_entries(log)) == list(range(12))


def test_checkpoints_are_appended_with_growing_sizes(tmp_path: Path) -> None:
    fx = build(tmp_path, 7, checkpoint_at=(2, 5, 7))
    assert [c.size for c in fx.checkpoints()] == [2, 5, 7]


def test_reading_a_log_reports_the_bad_line_number(tmp_path: Path) -> None:
    fx = build(tmp_path, 3, checkpoint_at=())
    lines = fx.lines()
    lines[1] = lines[1].replace(b",", b", ", 1)
    fx.path.write_bytes(b"".join(lines))
    with pytest.raises(LogError, match="line 2"):
        read_entries(fx.path)


def test_a_log_id_must_be_a_short_name_without_control_characters(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    for bad in ("", "x" * 129, "a\nb", "a\x00b", "tab\there"):
        with pytest.raises(ValueError, match="log id"):
            LogWriter(tmp_path / "l.jsonl", key, bad)


def test_checkpoints_taken_while_other_processes_append_are_never_out_of_order_or_torn(tmp_path: Path) -> None:
    fx = build(tmp_path, 0, checkpoint_at=())
    steady = lambda: fx.clock.now + timedelta(0)  # noqa: E731

    def append_work(worker: int) -> None:
        w = LogWriter(fx.path, fx.key, fx.log_id, steady)
        for i in range(30):
            w.append({"worker": worker, "i": i})

    def checkpoint_work(_: int) -> None:
        w = LogWriter(fx.path, fx.key, fx.log_id, steady)
        for _i in range(15):
            w.checkpoint()

    with ThreadPoolExecutor(8) as pool:
        futures = [pool.submit(append_work, n) for n in range(4)] + [pool.submit(checkpoint_work, n) for n in range(4)]
        for f in futures:
            f.result(timeout=120)  # re-raises any error a worker hit, such as a half-written line
    report = verify_log(fx.path.read_bytes(), fx.pub, fx.log_id, fx.checkpoints())
    assert report.ok, report.findings
    assert report.entries == 120 and report.checkpoints_checked == 60
    sizes = [c.size for c in fx.checkpoints()]
    assert sizes == sorted(sizes)


def test_a_half_written_checkpoint_file_blocks_new_checkpoints_until_repaired(tmp_path: Path) -> None:
    fx = build(tmp_path, 3, checkpoint_at=(3,))
    good = fx.cp_path.read_bytes()
    fx.cp_path.write_bytes(good + b'{"size":')  # a crash part-way through writing a checkpoint
    with pytest.raises(LogError, match="middle of an entry"):
        fx.writer().checkpoint()
    assert fx.cp_path.read_bytes() == good + b'{"size":'  # nothing was appended onto the fragment
    assert repair_tail(fx.cp_path) == len(b'{"size":')
    fx.writer().checkpoint()
    assert [c.size for c in fx.checkpoints()] == [3, 3]


def test_a_checkpoint_is_refused_when_the_clock_is_earlier_than_the_last_one(tmp_path: Path) -> None:
    fx = build(tmp_path, 3, checkpoint_at=(3,))
    with pytest.raises(LogError, match="earlier than the last checkpoint"):
        LogWriter(fx.path, fx.key, fx.log_id, Clock("2020-01-01T00:00:00Z")).checkpoint()
    assert (
        len(fx.checkpoints()) == 1
    )  # and the writer never produces a sidecar its own verifier would call out of order


def test_a_corrupt_last_checkpoint_is_reported_not_extended(tmp_path: Path) -> None:
    fx = build(tmp_path, 3, checkpoint_at=(3,))
    fx.cp_path.write_bytes(fx.cp_path.read_bytes().replace(b'"size":3', b'"size": 3'))
    with pytest.raises(LogError, match="unreadable"):
        fx.writer().checkpoint()


def test_creating_a_new_log_syncs_its_directory_as_well_as_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced_directories = 0
    real_fsync = os.fsync

    def spy(fd: int) -> None:
        nonlocal synced_directories
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            synced_directories += 1
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    key = Ed25519PrivateKey.generate()
    writer = LogWriter(tmp_path / "new.jsonl", key, "audit", Clock())
    writer.append({"first": True})
    assert synced_directories == 1  # the directory entry of the new file
    writer.append({"second": True})
    assert synced_directories == 1  # an existing file needs no directory sync
    writer.checkpoint()
    assert synced_directories == 2  # the new checkpoint file
