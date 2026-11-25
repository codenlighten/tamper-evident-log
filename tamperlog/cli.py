"""Command line: ``python -m tamperlog --help``.

Exit status: 0 success (or a log that verifies), 1 verification failed, 2 usage or file error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .canonical import CanonicalError, parse_json
from .keys import KeyError_, generate, load_public_key, load_signing_key, public_hex
from .log import LogError, LogWriter, checkpoint_path, read_checkpoints, read_entries, repair_tail
from .proofs import load_package, make_proof, verify_proof
from .verify import verify_log


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tamperlog", description="A signed, hash-chained, append-only log with an offline verifier."
    )
    sub = p.add_subparsers(dest="command", required=True)

    k = sub.add_parser("keygen", help="create an Ed25519 key pair")
    k.add_argument("--private", type=Path, required=True)
    k.add_argument("--public", type=Path, required=True)

    a = sub.add_parser("append", help="add one entry")
    a.add_argument("--log", type=Path, required=True)
    a.add_argument("--key", type=Path, required=True)
    a.add_argument("--log-id", required=True, help="the log's name; it is signed into every entry")
    a.add_argument("--payload", help="the entry's JSON payload; read from standard input if omitted")

    c = sub.add_parser("checkpoint", help="sign the current size and Merkle root")
    c.add_argument("--log", type=Path, required=True)
    c.add_argument("--key", type=Path, required=True)
    c.add_argument("--log-id", required=True)

    v = sub.add_parser("verify", help="verify a log against the writer's public key")
    v.add_argument("--log", type=Path, required=True)
    v.add_argument("--pubkey", type=Path, required=True)
    v.add_argument("--log-id", required=True, help="the id the log must have been written under")
    v.add_argument("--checkpoints", type=Path, help="default: LOG.checkpoints if it exists")
    v.add_argument("--json", action="store_true", help="machine-readable output")

    pr = sub.add_parser("prove", help="make an inclusion proof for one entry")
    pr.add_argument("--log", type=Path, required=True)
    pr.add_argument("--checkpoints", type=Path)
    pr.add_argument("--index", type=int, required=True)

    vp = sub.add_parser("verify-proof", help="check an inclusion proof using only the public key")
    vp.add_argument("proof", type=Path)
    vp.add_argument("--pubkey", type=Path, required=True)
    vp.add_argument("--log-id", required=True)

    r = sub.add_parser(
        "repair", help="cut a half-written last line (from a crash) off the end of a log or checkpoint file"
    )
    r.add_argument("--log", type=Path, required=True)
    return p


def _say(text: str) -> None:
    print(text)


def _run(args: argparse.Namespace) -> int:
    if args.command == "keygen":
        pub = generate(args.private, args.public)
        _say(f"public key {public_hex(pub)}")
        return 0
    if args.command == "append":
        raw = args.payload if args.payload is not None else sys.stdin.read()
        entry = LogWriter(args.log, load_signing_key(args.key), args.log_id).append(parse_json(raw.encode("utf-8")))
        _say(f"entry {entry.seq} hash {entry.hash}")
        return 0
    if args.command == "checkpoint":
        cp = LogWriter(args.log, load_signing_key(args.key), args.log_id).checkpoint()
        _say(f"checkpoint size {cp.size} root {cp.root}")
        return 0
    if args.command == "verify":
        cp_file = args.checkpoints or checkpoint_path(args.log)
        report = verify_log(args.log.read_bytes(), load_public_key(args.pubkey), args.log_id, read_checkpoints(cp_file))
        if args.json:
            _say(
                json.dumps(
                    {
                        "ok": report.ok,
                        "entries": report.entries,
                        "checkpoints_checked": report.checkpoints_checked,
                        "head": report.head,
                        "findings": [f.__dict__ for f in report.findings],
                    },
                    indent=2,
                )
            )
        else:
            for f in report.findings:
                where = "" if f.seq is None else f" [{f.seq}]"
                _say(f"{f.code}{where}: {f.detail}")
            verdict = "OK" if report.ok else "FAILED"
            _say(f"{verdict}: {report.entries} entries, {report.checkpoints_checked} checkpoints checked")
        return 0 if report.ok else 1
    if args.command == "prove":
        entries = read_entries(args.log)
        cps = read_checkpoints(args.checkpoints or checkpoint_path(args.log))
        usable = [c for c in cps if c.size > args.index and c.size <= len(entries)]
        if not usable:
            _say(f"no checkpoint covers entry {args.index}; run `tamperlog checkpoint` first")
            return 2
        print(json.dumps(make_proof(entries, args.index, usable[-1]), indent=2))
        return 0
    if args.command == "verify-proof":
        reason = verify_proof(load_package(args.proof.read_bytes()), load_public_key(args.pubkey), args.log_id)
        _say("OK: the proof is valid" if reason is None else f"FAILED: {reason}")
        return 0 if reason is None else 1
    if args.command == "repair":
        removed = repair_tail(args.log)
        _say(f"removed {removed} bytes of partial entry" if removed else "nothing to repair")
        return 0
    raise AssertionError(args.command)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except (KeyError_, LogError, CanonicalError, OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
