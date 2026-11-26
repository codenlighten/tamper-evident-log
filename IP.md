# IP records

| Date | Covers | Type | Record hash | Signer | Tag |
|---|---|---|---|---|---|
| 2026-11-26 | Commit `f53d1a7`: a signed, hash-chained log with Merkle checkpoints and proofs, implementation, tests and documentation. No authorship claimed in the published methods used (RFC 6962 trees, Ed25519), Certificate Transparency reference test values and third-party libraries. | software, hash-only | [`5ae0fb0496f3b206be4650e3a78692e774e4973504aeca5816dddc1af495bb2d`](https://iptrust.org/v/5ae0fb0496f3b206be4650e3a78692e774e4973504aeca5816dddc1af495bb2d) | Gregory J. Ward | `ip-2026-11-26` |

A record is evidence that the committed content existed by the time of its anchor and that the signer made
the statement; it does not create or register any right. Anchoring completes some hours after submission.
Files under `third_party/`, where present, are not part of the record.

## Verifying

Verification needs the evidence package for the record, which the author holds and which is not committed
here. With it in `.iptrust/`:

```
git worktree add /tmp/at-tag-tamper-evident-log ip-2026-11-26
cp -r .iptrust /tmp/at-tag-tamper-evident-log/
(cd /tmp/at-tag-tamper-evident-log && iptrust2 verify 5ae0fb0496f3b206be4650e3a78692e774e4973504aeca5816dddc1af495bb2d --fetch-headers)
git worktree remove --force /tmp/at-tag-tamper-evident-log
```

Expect `verdict: valid` and `content: matched` once both chains have anchored.
