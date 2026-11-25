# tamper-evident-log: a signed, hash-chained log with checkpoints and an offline verifier

An append-only log where every entry is hashed, chained to the one before it and signed with Ed25519; signed Merkle checkpoints (RFC 6962 trees, with inclusion and consistency proofs) that can show truncation; and a verifier that needs only the log file and a public key.

It shows security engineering as evidence: not a claim that nothing can go wrong, but a table of attacks, what the verifier says about each, and the cases it **cannot** detect, each with a test.

## What it does and does not prove

A log that verifies tells you: *these entries were written, in this order and without change, by the holder of this public key, for this log id.* With a trusted checkpoint it also tells you the log has not been cut back or rewritten before that checkpoint.

It does **not** tell you:

- **That nothing was cut off the end**, unless you hold a checkpoint the attacker could not delete. The `.checkpoints` file beside the log is a convenience, not such an anchor: publish checkpoints somewhere the log's storage cannot reach (another organisation, a notice board, a public ledger).
- **That entries newer than your latest trusted checkpoint are genuine**, if someone holds the signing key.
- **That the times are true.** A time is whatever the writer's clock said; it is signed, not independently attested.
- **Which key to trust.** A log rewritten end to end under an attacker's own key verifies against the attacker's key. The public key and the log id must come from outside the log.

Calling a log tamper-*evident* is only honest under those conditions, so they are stated here and tested below.

## Run it

Needs Python 3.12 and a POSIX system (it uses `fcntl` file locks). I ran it only on Linux; macOS should work but is untested.

```bash
pip install -e ".[dev]"
pytest                                   # 287 tests, about 8 seconds

tamperlog keygen --private writer.key --public writer.pub
echo '{"action":"login","user":"ann"}' | tamperlog append --log audit.jsonl --key writer.key --log-id payroll
tamperlog checkpoint --log audit.jsonl --key writer.key --log-id payroll
tamperlog verify --log audit.jsonl --pubkey writer.pub --log-id payroll          # exit 0 if it verifies, 1 if not
tamperlog prove --log audit.jsonl --index 0 > proof.json                          # a proof one entry is in the log
tamperlog verify-proof proof.json --pubkey writer.pub --log-id payroll            # needs no access to the log
```

`verify` prints findings with stable codes and ends with a line like `OK: 5 entries, 1 checkpoints checked`, or `FAILED` after codes such as `BAD_HASH [2]`. `--json` gives machine-readable output. Exit status: 0 success, 1 verification failed, 2 usage or file error.

## How it works

Each line of the log is one entry, in canonical JSON, with a newline:

```
{"hash":"…","payload":{…},"prev":"<hash of the previous entry>","seq":0,"sig":"…","time":"2026-11-25T15:00:00Z"}
```

- **Hash chain.** `hash = SHA-256(domain ‖ canonical({log, seq, time, payload, prev}))`. Changing, removing or reordering anything changes every later hash.
- **Signature.** Ed25519 over a differently prefixed copy of the hash. Entry hashes, entry signatures and checkpoint signatures use three distinct domain prefixes, so a value valid in one role is never valid in another.
- **Log id.** A name for the log, signed into every entry and checkpoint but not stored in each line: the verifier supplies the id it expects. Without it, two logs signed with the same key would be interchangeable (found by an independent review, below).
- **Strict canonical form.** The verifier requires each line to be *exactly* the canonical encoding of its content: sorted keys, no whitespace, no floats, integers within 53 bits, no duplicate keys, no non-UTF-8. So any changed byte is a finding, and a fuzz test can state that as a property.
- **Checkpoints.** A signed `(log id, size, Merkle root, time)`. The root is an RFC 6962 tree over the entry hashes. An inclusion proof shows one entry is in the tree; a consistency proof shows one tree is a prefix of a later one, so history was only appended to. The Merkle code follows RFC 6962 (generation) and RFC 9162 (verification).
- **One nuance worth knowing.** A Merkle root does not commit to the tree size: a different size with the same proof shape accepts the same root. That is why a proof is always checked against a *signed* `(size, root)` pair, never a bare root. A test pins this.

| Finding code | Meaning |
|---|---|
| `BAD_FORMAT` | Not canonical JSON, wrong fields, or bad line framing |
| `BAD_SEQ`, `BAD_PREV` | Entry numbers or links are not an unbroken chain |
| `BAD_HASH` | An entry's content does not match its hash |
| `BAD_SIGNATURE` | Not signed by the key you supplied |
| `BAD_TIME_ORDER` | Time runs backwards |
| `CHECKPOINT_BAD_SIGNATURE` | A checkpoint was not signed by the key (or is for another log id) |
| `CHECKPOINT_BEYOND_LOG` | The log is shorter than a checkpoint says it was: truncated |
| `CHECKPOINT_ROOT_MISMATCH` | The log's early entries no longer match a checkpoint: rewritten |
| `CHECKPOINT_ORDER` | Checkpoints shrink or go back in time |

## The tamper matrix

Each row is a test (`tests/test_tamper.py`). The last block is what the design **cannot** catch.

| What the attacker does | Result |
|---|---|
| Edits a payload | `BAD_HASH` at that entry |
| Edits it and recomputes the hash | `BAD_SIGNATURE`, `BAD_PREV` at the next entry, checkpoint mismatch |
| Edits it and re-signs with their own key | `BAD_SIGNATURE`, `BAD_PREV` |
| Flips one character of a signature or a hash | `BAD_SIGNATURE` / `BAD_HASH` |
| Swaps, deletes, duplicates or reorders entries | `BAD_SEQ`, `BAD_PREV` |
| Rewrites the whole tail with their own key | `BAD_SIGNATURE` on every rewritten entry, checkpoint mismatch |
| Passes off another log signed by the same key | `BAD_HASH` on every entry, `CHECKPOINT_BAD_SIGNATURE` (log id) |
| Moves time backwards, even holding the key | `BAD_TIME_ORDER` |
| Adds a space, reorders keys, adds a field, a BOM, CRLF line endings, a blank line, invalid UTF-8, a duplicate key | `BAD_FORMAT` |
| Cuts entries off the end, with a checkpoint held | `CHECKPOINT_BEYOND_LOG` |
| Rewrites history before a checkpoint, with a stolen key | `CHECKPOINT_ROOT_MISMATCH` |
| Forges, resigns or reorders checkpoints | `CHECKPOINT_BAD_SIGNATURE` / `CHECKPOINT_ORDER` |
| **Cuts entries off the end, no checkpoint held** | **Not detected** (a shorter chain is still a valid chain) |
| **Rolls back the log and its checkpoints together** | **Not detected** (nothing inside the files can object) |
| **Rewrites entries newer than the latest checkpoint, with a stolen key** | **Not detected** |
| **Rewrites the whole log under their own key, verified against that key** | **Verifies**: the key must be trusted from outside |

## Tests

287 tests pass; `ruff`, `ruff format --check` and strict `mypy` are clean. Run on a Linux machine, three runs in a row (about 8.2 s each).

- **Merkle:** the roots match the Certificate Transparency reference values for trees of 1 to 8 leaves; every inclusion proof verifies for every tree size up to 70, and every consistency proof for every pair of sizes up to 40; an independent stack-based implementation agrees with the recursive one up to 129 leaves; any change to a proof or a size that alters its shape fails.
- **Fuzzing (deterministic, replayable):** about 4,000 random modifications of a log with a covering checkpoint (bit flips, byte edits, deletions, insertions, whole-line deletion, duplication, swaps and replacements): **every** one was detected. Without a checkpoint, every one was detected except cutting whole entries off the end. About 1,500 garbage inputs never crashed the verifier. About 3,000 single-character changes to a proof package were tried, and every change that altered its meaning was rejected.
- **Format pinned independently:** `tests/test_spec.py` rebuilds the hash and signed-message formats from the standard library, so changing a domain string in the writer and verifier together is a visible, deliberate act.
- **Concurrency:** eight threads and twelve separate processes appending to one log, and checkpoints taken while others append, always produce a log that verifies.
- **Crash recovery:** a half-written entry or checkpoint blocks further writes until repaired, and nothing is ever appended onto a fragment.

### What running it found

- Two of my own Merkle tests assumed a wrong tree size must fail. It need not (see the nuance above); the tests now assert the real property.
- One branch of the canonical encoder only supplied an error message. Removing it changed no behaviour and no test noticed; a test now pins the message, and a real "floats are accepted" break fails six tests.
- Lint and strict type-checking found the usual small things.

### Two independent reviews

An independent AI review (a different model, asked for real flaws with concrete attacks) was run twice. It found no forgery in the cryptography, and 10 real problems in the design around it, all fixed and tested:

| Finding | Fix |
|---|---|
| Two logs signed with one key were interchangeable (no log identity in what is signed) | A log id is signed into every entry and checkpoint; the verifier must be given it |
| `checkpoint()` ignored the log lock: torn reads, out-of-order checkpoints | One lock held from reading the entries to the fsynced checkpoint; concurrency test |
| The proof verifier could raise on an unencodable payload | Entry parsing validates payloads; proofs return a reason |
| A malformed checkpoint object raised instead of failing | Reported as `CHECKPOINT_BAD_SIGNATURE` |
| The empty-tree consistency case accepted any claimed root | Requires the defined empty root |
| The writer's "refuses a bad tail" claim was too broad | Narrowed to what it checks (the last entry); the verifier and external checkpoints cover the rest |
| `max_findings=0` made the verifier report success without checking | A limit below 1 is refused; the limit only caps reporting |
| A crash mid-checkpoint poisoned the checkpoint file | The writer refuses to append onto a half-written line, and `repair` fixes it |
| The writer could emit checkpoints its own verifier calls out of order | Refused when the clock is earlier than the last checkpoint |
| "Flushed to disk" ignored the directory entry of a new file | The directory is fsynced on creation; the claim is qualified |

### Deliberate breaks

31 changes were made one at a time to the code, the whole suite run and the code restored (287 of 287 pass afterwards). Every one failed at least one test, and the test that catches each is the one you would expect:

- **Formats:** each of the three domain prefixes removed; the log id dropped from the hash.
- **Verifier checks disabled one by one:** signatures, hash recomputation, `prev` links, sequence numbers, time order, checkpoint roots, "log shorter than a checkpoint", and a findings limit of 0.
- **Canonical encoding:** unsorted keys; floats accepted (two variants); canonical form not required; duplicate keys accepted; an unencodable payload accepted when parsing.
- **Merkle:** inner nodes hashed like leaves; leftover proof steps ignored; an "empty tree" with any root.
- **Keys and files:** a world-readable private key accepted; the clock allowed to run backwards; appends without a lock; checkpoints without a lock; half-written checkpoint files appended onto; checkpoint time allowed to go backwards; a new file's directory not synced (twice).
- **Proofs and checkpoints:** proofs that skip the entry's signature; a malformed checkpoint signature raising.

## Limits

- One writer key, no rotation, no revocation, no multi-party signing. If the key is stolen, history after your latest trusted checkpoint cannot be trusted.
- No trusted timestamping. Times are signed assertions by the writer.
- Anchoring checkpoints outside the log's storage is your responsibility and the part that matters most.
- The writer checks only the last entry before appending (so appends stay constant-time); run `verify` regularly.
- Ed25519 comes from the `cryptography` package; I did not analyse it or its side channels, and this code has not been audited. It is a demonstration of the design and its tests, not a replacement for a mature transparency-log system.
- POSIX only (`fcntl`), and tested only on Linux. Durability is as good as the filesystem's `fsync`.
- No performance numbers are claimed; none were measured.

## Layout

```
tamperlog/   canonical.py (encoding)  entry.py (hashes, signatures)  checkpoint.py  merkle.py
             log.py (writer, reader, repair)  verify.py (offline verifier)  proofs.py  keys.py  cli.py
tests/       tests/test_tamper.py is the attack matrix; test_spec.py pins the formats
```

## Dependencies

`cryptography` at run time; `pytest`, `ruff` and `mypy` for development. All are public packages; none of their code is copied here.

## Licence

MIT. See `LICENSE`.
