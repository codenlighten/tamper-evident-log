"""The command line, end to end, in real subprocesses."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

LOG_ID = "audit"


def run(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tamperlog", *args], input=stdin, capture_output=True, text=True, timeout=60
    )


def setup(tmp_path: Path, entries: int = 5) -> tuple[Path, Path, Path]:
    priv, pub, log = tmp_path / "w.key", tmp_path / "w.pub", tmp_path / "audit.jsonl"
    assert run("keygen", "--private", str(priv), "--public", str(pub)).returncode == 0
    for i in range(entries):
        r = run(
            "append",
            "--log",
            str(log),
            "--key",
            str(priv),
            "--log-id",
            LOG_ID,
            "--payload",
            json.dumps({"action": "login", "n": i}),
        )
        assert r.returncode == 0, r.stderr
    return priv, pub, log


def test_the_whole_workflow(tmp_path: Path) -> None:
    priv, pub, log = setup(tmp_path)
    assert run("checkpoint", "--log", str(log), "--key", str(priv), "--log-id", LOG_ID).returncode == 0
    r = run("verify", "--log", str(log), "--pubkey", str(pub), "--log-id", LOG_ID)
    assert r.returncode == 0 and "OK: 5 entries, 1 checkpoints checked" in r.stdout

    proof = run("prove", "--log", str(log), "--index", "2")
    assert proof.returncode == 0, proof.stderr
    proof_file = tmp_path / "proof.json"
    proof_file.write_text(proof.stdout)
    ok = run("verify-proof", str(proof_file), "--pubkey", str(pub), "--log-id", LOG_ID)
    assert ok.returncode == 0 and "the proof is valid" in ok.stdout

    forged = json.loads(proof.stdout)
    forged["entry"]["payload"] = {"action": "admin"}
    proof_file.write_text(json.dumps(forged))
    bad = run("verify-proof", str(proof_file), "--pubkey", str(pub), "--log-id", LOG_ID)
    assert bad.returncode == 1 and "FAILED" in bad.stdout


def test_a_modified_log_exits_with_status_1_and_names_the_problem(tmp_path: Path) -> None:
    _, pub, log = setup(tmp_path)
    log.write_bytes(log.read_bytes().replace(b'"n":2', b'"n":7'))
    r = run("verify", "--log", str(log), "--pubkey", str(pub), "--log-id", LOG_ID)
    assert r.returncode == 1
    assert "BAD_HASH [2]" in r.stdout and "FAILED" in r.stdout


def test_json_output_is_machine_readable(tmp_path: Path) -> None:
    _, pub, log = setup(tmp_path, 3)
    out = json.loads(run("verify", "--log", str(log), "--pubkey", str(pub), "--log-id", LOG_ID, "--json").stdout)
    assert out["ok"] is True and out["entries"] == 3 and out["findings"] == []
    log.write_bytes(log.read_bytes()[:-5])
    out = json.loads(run("verify", "--log", str(log), "--pubkey", str(pub), "--log-id", LOG_ID, "--json").stdout)
    assert out["ok"] is False and out["findings"][0]["code"] == "BAD_FORMAT"


def test_truncation_is_caught_once_a_checkpoint_exists(tmp_path: Path) -> None:
    priv, pub, log = setup(tmp_path, 6)
    assert run("checkpoint", "--log", str(log), "--key", str(priv), "--log-id", LOG_ID).returncode == 0
    lines = log.read_bytes().splitlines(keepends=True)
    log.write_bytes(b"".join(lines[:4]))
    r = run("verify", "--log", str(log), "--pubkey", str(pub), "--log-id", LOG_ID)
    assert r.returncode == 1 and "CHECKPOINT_BEYOND_LOG" in r.stdout


def test_a_group_readable_private_key_is_refused_with_advice(tmp_path: Path) -> None:
    priv, _, log = setup(tmp_path, 1)
    os.chmod(priv, 0o644)
    r = run("append", "--log", str(log), "--key", str(priv), "--log-id", LOG_ID, "--payload", "{}")
    assert r.returncode == 2 and "chmod 600" in r.stderr


def test_usage_and_file_errors_exit_with_status_2_and_a_message(tmp_path: Path) -> None:
    assert (
        run(
            "verify", "--log", str(tmp_path / "missing.jsonl"), "--pubkey", str(tmp_path / "x.pub"), "--log-id", LOG_ID
        ).returncode
        == 2
    )
    priv, _, log = setup(tmp_path, 1)
    r = run("append", "--log", str(log), "--key", str(priv), "--log-id", LOG_ID, "--payload", "[1.5]")
    assert r.returncode == 2 and "floating-point" in r.stderr
    r = run("append", "--log", str(log), "--key", str(priv), "--log-id", LOG_ID, stdin='{"from":"stdin"}')
    assert r.returncode == 0
    assert run("prove", "--log", str(log), "--index", "0").returncode == 2  # no checkpoint yet


def test_repair_removes_a_partial_entry(tmp_path: Path) -> None:
    _, pub, log = setup(tmp_path, 2)
    good = log.read_bytes()
    log.write_bytes(good + b'{"seq":2')
    assert run("verify", "--log", str(log), "--pubkey", str(pub), "--log-id", LOG_ID).returncode == 1
    assert "removed 8 bytes" in run("repair", "--log", str(log)).stdout
    assert log.read_bytes() == good
    assert run("verify", "--log", str(log), "--pubkey", str(pub), "--log-id", LOG_ID).returncode == 0


def test_the_wrong_log_id_fails_verification(tmp_path: Path) -> None:
    _, pub, log = setup(tmp_path, 3)
    r = run("verify", "--log", str(log), "--pubkey", str(pub), "--log-id", "a-different-log")
    assert r.returncode == 1 and "BAD_HASH" in r.stdout
    assert run("verify", "--log", str(log), "--pubkey", str(pub)).returncode == 2  # the id is required, not optional
    r = run("append", "--log", str(log), "--key", str(tmp_path / "w.key"), "--log-id", "")
    assert r.returncode == 2 and "log id" in r.stderr
