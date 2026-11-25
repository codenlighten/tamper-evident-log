"""The tamper matrix: what an attacker can do to a log file, and what the verifier says.

Most cases must be detected, each with its own finding code. A few are NOT detectable by design, and are
tested as such (their names say so), because a security tool should state its limits with evidence.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tamperlog import verify as v
from tamperlog.checkpoint import Checkpoint, make_checkpoint
from tamperlog.entry import Entry, compute_hash, make_entry
from tamperlog.log import LogWriter, checkpoint_path, read_checkpoints
from tamperlog.verify import Report, verify_log

from .helpers import Fixture, build, rechain, time_plus, to_bytes

Mutator = Callable[[list[bytes]], list[bytes]]


def codes(report: Report) -> set[str]:
    return {f.code for f in report.findings}


def where(report: Report, code: str) -> set[int | None]:
    return {f.seq for f in report.findings if f.code == code}


@pytest.fixture
def fx(tmp_path: Path) -> Fixture:
    return build(tmp_path, 10, checkpoint_at=(4, 10))


def check(
    fx: Fixture, data: bytes | None = None, cps: list[Checkpoint] | None = None, key: Ed25519PrivateKey | None = None
) -> Report:
    pub = (key or fx.key).public_key()
    return verify_log(
        fx.path.read_bytes() if data is None else data, pub, fx.log_id, fx.checkpoints() if cps is None else cps
    )


def test_an_untouched_log_with_checkpoints_verifies(fx: Fixture) -> None:
    r = check(fx)
    assert r.ok and r.entries == 10 and r.checkpoints_checked == 2 and r.findings == []


# --- changes to one entry ------------------------------------------------------------------------------


def test_changing_a_payload_breaks_that_entrys_hash(fx: Fixture) -> None:
    data = fx.path.read_bytes().replace(b'"n":3', b'"n":9')
    r = check(fx, data)
    assert codes(r) == {v.BAD_HASH} and where(r, v.BAD_HASH) == {3}


def test_changing_a_payload_and_recomputing_the_hash_breaks_the_signature_and_the_next_link(fx: Fixture) -> None:
    es = fx.entries()
    e = es[3]
    forged = Entry(
        e.seq,
        e.time,
        {"event": "step", "n": 99},
        e.prev,
        compute_hash(fx.log_id, e.seq, e.time, {"event": "step", "n": 99}, e.prev).hex(),
        e.sig,
    )
    r = check(fx, to_bytes([*es[:3], forged, *es[4:]]))
    assert where(r, v.BAD_SIGNATURE) == {3}
    assert where(r, v.BAD_PREV) == {4}
    assert where(r, v.CP_ROOT_MISMATCH) == {0, 1}  # both checkpoints cover entry 3


def test_changing_a_payload_and_resigning_with_the_attackers_own_key_is_still_caught(fx: Fixture) -> None:
    attacker = Ed25519PrivateKey.generate()
    es = fx.entries()
    forged = make_entry(fx.log_id, 3, es[3].time, {"event": "step", "n": 99}, es[3].prev, attacker)
    r = check(fx, to_bytes([*es[:3], forged, *es[4:]]))
    assert where(r, v.BAD_SIGNATURE) == {3}
    assert where(r, v.BAD_PREV) == {4}


def test_flipping_one_character_of_a_signature_is_caught(fx: Fixture) -> None:
    lines = fx.lines()
    e = fx.entries()[6]
    bad = e.sig[:-1] + ("0" if e.sig[-1] != "0" else "1")
    lines[6] = lines[6].replace(e.sig.encode(), bad.encode())
    r = check(fx, b"".join(lines))
    assert codes(r) == {v.BAD_SIGNATURE} and where(r, v.BAD_SIGNATURE) == {6}


def test_flipping_one_character_of_a_hash_is_caught_at_that_entry_and_the_next(fx: Fixture) -> None:
    lines = fx.lines()
    e = fx.entries()[5]
    bad = ("0" if e.hash[0] != "0" else "1") + e.hash[1:]
    lines[5] = lines[5].replace(f'"hash":"{e.hash}"'.encode(), f'"hash":"{bad}"'.encode())
    r = check(fx, b"".join(lines))
    assert where(r, v.BAD_HASH) == {5}
    assert where(r, v.BAD_PREV) == {6}


def test_moving_time_backwards_is_caught_even_when_the_attacker_holds_the_key(fx: Fixture) -> None:
    es = fx.entries()
    early = make_entry(fx.log_id, 5, time_plus(es[0].time, -3600), es[5].payload, es[5].prev, fx.key)
    redone = rechain(fx.log_id, [*es[:5], early, *es[6:]], 6, fx.key)
    r = check(fx, to_bytes(redone))
    assert where(r, v.BAD_TIME_ORDER) == {5}


# --- changes to the order or the set of entries --------------------------------------------------------


def test_swapping_two_entries_is_caught(fx: Fixture) -> None:
    lines = fx.lines()
    lines[4], lines[5] = lines[5], lines[4]
    r = check(fx, b"".join(lines))
    assert {4, 5} <= where(r, v.BAD_SEQ)
    assert v.BAD_PREV in codes(r)


def test_deleting_a_middle_entry_is_caught(fx: Fixture) -> None:
    lines = fx.lines()
    del lines[5]
    r = check(fx, b"".join(lines))
    assert 5 in where(r, v.BAD_SEQ) and 5 in where(r, v.BAD_PREV)
    assert where(r, v.CP_BEYOND_LOG) == {1}  # the log is now shorter than checkpoint 1 says


def test_deleting_the_first_entry_is_caught(fx: Fixture) -> None:
    lines = fx.lines()
    del lines[0]
    r = check(fx, b"".join(lines))
    assert 0 in where(r, v.BAD_SEQ) and 0 in where(r, v.BAD_PREV)


def test_duplicating_an_entry_is_caught(fx: Fixture) -> None:
    lines = fx.lines()
    r = check(fx, b"".join([*lines, lines[-1]]))
    assert 10 in where(r, v.BAD_SEQ) and 10 in where(r, v.BAD_PREV)


def test_rewriting_the_whole_suffix_with_the_attackers_key_is_caught_by_the_real_public_key(fx: Fixture) -> None:
    attacker = Ed25519PrivateKey.generate()
    redone = rechain(fx.log_id, fx.entries(), 6, attacker, edits={7: {"event": "forged"}})
    r = check(fx, to_bytes(redone))
    assert where(r, v.BAD_SIGNATURE) == {6, 7, 8, 9}
    assert where(r, v.CP_ROOT_MISMATCH) == {1}


# --- truncation: only a checkpoint can show it ---------------------------------------------------------


def test_cutting_entries_off_the_end_is_NOT_detectable_without_a_checkpoint(fx: Fixture) -> None:
    """A hash chain proves what is there, not what used to be there. This is why checkpoints exist."""
    data = b"".join(fx.lines()[:7])
    assert verify_log(data, fx.pub, fx.log_id).ok


def test_cutting_entries_off_the_end_is_detected_by_a_checkpoint(fx: Fixture) -> None:
    data = b"".join(fx.lines()[:9])
    r = check(fx, data)
    assert where(r, v.CP_BEYOND_LOG) == {1}


def test_truncating_below_an_older_checkpoint_is_detected_by_both(fx: Fixture) -> None:
    r = check(fx, b"".join(fx.lines()[:3]))
    assert where(r, v.CP_BEYOND_LOG) == {0, 1}


def test_an_empty_log_cannot_satisfy_a_checkpoint(fx: Fixture) -> None:
    assert where(check(fx, b""), v.CP_BEYOND_LOG) == {0, 1}


def test_rolling_back_both_the_log_and_the_checkpoints_together_is_NOT_detectable(fx: Fixture) -> None:
    """If the attacker can also change what you hold as checkpoints, nothing inside the files can object.
    Publish checkpoints somewhere the writer cannot edit."""
    assert check(fx, b"".join(fx.lines()[:4]), fx.checkpoints()[:1]).ok


# --- an attacker who HAS the signing key ---------------------------------------------------------------


def test_rewriting_history_before_a_checkpoint_with_a_stolen_key_is_detected_by_the_checkpoint(fx: Fixture) -> None:
    redone = rechain(fx.log_id, fx.entries(), 2, fx.key, edits={2: {"event": "rewritten"}})
    r = check(fx, to_bytes(redone))
    assert codes(r) == {v.CP_ROOT_MISMATCH}
    assert where(r, v.CP_ROOT_MISMATCH) == {0, 1}


def test_rewriting_entries_newer_than_the_latest_checkpoint_with_a_stolen_key_is_NOT_detectable(tmp_path: Path) -> None:
    fx = build(tmp_path, 10, checkpoint_at=(4,))
    redone = rechain(fx.log_id, fx.entries(), 6, fx.key, edits={7: {"event": "rewritten"}})
    assert check(fx, to_bytes(redone)).ok


def test_a_log_rewritten_end_to_end_with_the_attackers_own_key_verifies_against_the_attackers_key(
    tmp_path: Path,
) -> None:
    """Verification answers "was this written by the holder of THIS public key". Which key to trust is
    decided outside the log."""
    fx = build(tmp_path, 5, checkpoint_at=())
    attacker = Ed25519PrivateKey.generate()
    forged = to_bytes(rechain(fx.log_id, fx.entries(), 0, attacker, edits={1: {"event": "forged"}}))
    assert verify_log(forged, attacker.public_key(), fx.log_id).ok
    assert where(verify_log(forged, fx.pub, fx.log_id), v.BAD_SIGNATURE) == {0, 1, 2, 3, 4}


def test_the_wrong_public_key_rejects_everything(fx: Fixture) -> None:
    r = check(fx, key=Ed25519PrivateKey.generate())
    assert where(r, v.BAD_SIGNATURE) == set(range(10))
    assert where(r, v.CP_BAD_SIGNATURE) == {0, 1}


# --- malformed files -----------------------------------------------------------------------------------


def _edit_line(index: int, change: Callable[[bytes], bytes]) -> Mutator:
    def mutate(lines: list[bytes]) -> list[bytes]:
        lines = list(lines)
        lines[index] = change(lines[index])
        return lines

    return mutate


@pytest.mark.parametrize(
    "mutator",
    [
        pytest.param(_edit_line(3, lambda b: b.replace(b",", b", ", 1)), id="whitespace added"),
        pytest.param(_edit_line(3, lambda b: b.rstrip(b"\n") + b" \n"), id="trailing space"),
        pytest.param(_edit_line(3, lambda b: b"\xef\xbb\xbf" + b), id="byte order mark"),
        pytest.param(_edit_line(3, lambda b: b.replace(b'"seq":3,', b"")), id="field missing"),
        pytest.param(_edit_line(3, lambda b: b.replace(b'{"hash"', b'{"extra":1,"hash"', 1)), id="extra field"),
        pytest.param(_edit_line(3, lambda b: b.replace(b'"seq":3', b'"seq":"3"')), id="seq as a string"),
        pytest.param(_edit_line(3, lambda b: b.replace(b'"seq":3', b'"seq":3.0')), id="seq as a float"),
        pytest.param(_edit_line(3, lambda b: b.replace(b'"seq":3', b'"seq":true')), id="seq as a boolean"),
        pytest.param(_edit_line(3, lambda b: b.replace(b"2026-01-01T", b"2026-13-45T")), id="impossible date"),
        pytest.param(_edit_line(3, lambda b: b.replace(b'Z"', b'+00:00"', 1)), id="time zone spelled differently"),
        pytest.param(_edit_line(3, lambda b: b.replace(b'"hash":"', b'"hash":"A', 1)), id="hash with a wrong length"),
        pytest.param(_edit_line(3, lambda b: b.replace(b'"prev":"', b'"prev":"0', 1)), id="prev with a wrong length"),
        pytest.param(_edit_line(3, lambda b: b.replace(b'"seq":3', b'"seq":3,"seq":3', 1)), id="duplicate key"),
        pytest.param(_edit_line(3, lambda b: b"garbage\n"), id="garbage line"),
        pytest.param(_edit_line(3, lambda b: b"\n"), id="empty line"),
        pytest.param(lambda lines: [*lines[:3], b"\n", *lines[3:]], id="blank line inserted"),
        pytest.param(lambda lines: [*lines[:-1], lines[-1].rstrip(b"\n")], id="missing final newline"),
        pytest.param(lambda lines: [*lines, b'{"seq":10,"ti'], id="partial last entry"),
        pytest.param(lambda lines: [*lines[:3], b"\xff\xfe\n", *lines[3:]], id="invalid UTF-8"),
        pytest.param(lambda lines: [ln.replace(b"\n", b"\r\n") for ln in lines], id="CRLF line endings"),
    ],
)
def test_anything_but_the_exact_canonical_form_is_refused(fx: Fixture, mutator: Mutator) -> None:
    r = check(fx, b"".join(mutator(fx.lines())))
    assert not r.ok
    assert v.BAD_FORMAT in codes(r)


def test_key_order_shuffled_is_not_canonical(fx: Fixture) -> None:
    lines = fx.lines()
    obj = json.loads(lines[2])
    lines[2] = json.dumps(dict(reversed(list(obj.items()))), separators=(",", ":")).encode() + b"\n"
    assert v.BAD_FORMAT in codes(check(fx, b"".join(lines)))


# --- the checkpoints themselves ------------------------------------------------------------------------


def test_a_checkpoint_with_an_altered_root_or_size_loses_its_signature(fx: Fixture) -> None:
    cps = fx.checkpoints()
    wrong_root = Checkpoint(
        cps[1].size, ("0" if cps[1].root[0] != "0" else "1") + cps[1].root[1:], cps[1].time, cps[1].sig
    )
    wrong_size = Checkpoint(cps[1].size + 1, cps[1].root, cps[1].time, cps[1].sig)
    assert where(check(fx, cps=[cps[0], wrong_root]), v.CP_BAD_SIGNATURE) == {1}
    assert where(check(fx, cps=[cps[0], wrong_size]), v.CP_BAD_SIGNATURE) == {1}


def test_a_checkpoint_resigned_by_the_attacker_is_rejected(fx: Fixture) -> None:
    attacker = Ed25519PrivateKey.generate()
    fake = make_checkpoint(fx.log_id, fx.entries()[:5], attacker, fx.checkpoints()[0].time)
    assert where(check(fx, cps=[fake]), v.CP_BAD_SIGNATURE) == {0}


def test_checkpoints_that_shrink_or_go_back_in_time_are_rejected(fx: Fixture) -> None:
    older, newer = fx.checkpoints()
    assert where(check(fx, cps=[newer, older]), v.CP_ORDER) == {1}


# --- a log cannot be swapped for another log signed with the same key ---------------------------------


def test_another_logs_entries_and_checkpoints_do_not_verify_even_under_the_same_key(tmp_path: Path) -> None:
    """Two logs, one key. Without a log id in what is signed, B's valid file would pass as A."""
    a = build(tmp_path, 6, checkpoint_at=(6,), log_id="payroll")
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    b_path = other_dir / "log.jsonl"
    writer_b = LogWriter(b_path, a.key, "badges", a.clock)  # the SAME signing key, a different log
    for i in range(6):
        writer_b.append({"event": "step", "n": i})
    writer_b.checkpoint()
    b_data, b_cps = b_path.read_bytes(), read_checkpoints(checkpoint_path(b_path))

    assert verify_log(b_data, a.pub, "badges", b_cps).ok  # genuine, under its own id
    swapped = verify_log(b_data, a.pub, "payroll", b_cps)  # passed off as the payroll log
    assert where(swapped, v.BAD_HASH) == set(range(6))
    assert where(swapped, v.CP_BAD_SIGNATURE) == {0}


def test_a_malformed_checkpoint_object_is_reported_not_raised(fx: Fixture) -> None:
    cp = fx.checkpoints()[0]
    junk = Checkpoint(cp.size, cp.root, cp.time, "not hex")
    assert where(check(fx, cps=[junk]), v.CP_BAD_SIGNATURE) == {0}


def test_a_findings_limit_can_never_switch_checking_off(fx: Fixture) -> None:
    forged = fx.path.read_bytes().replace(b'"n":3', b'"n":9')
    with pytest.raises(ValueError, match="at least 1"):
        verify_log(forged, fx.pub, fx.log_id, max_findings=0)
    capped = verify_log(forged, fx.pub, fx.log_id, max_findings=1)
    assert not capped.ok and len(capped.findings) == 1
