# Stateful cross-core replay and close inspection

The `sage-exchange -stateful` mode runs a live legacy record sequence from Go to
Rust and Rust to Go, with both c2s and s2c roles. At the pinned core revisions, all
four trials passed: **36 receiver actions and four independent fresh-record
positive controls**. This covers replay and explicit close only, not expiry,
concurrent races, restart/recovery or full protocol conformance.

```sh
go build -o /tmp/sage-exchange ./cmd/sage-exchange
/tmp/sage-exchange -stateful \
  -go-adapter /absolute/path/to/go-adapter \
  -rust-adapter /absolute/path/to/rust-adapter \
  -go-revision ACTUAL_GO_COMMIT -rust-revision ACTUAL_RUST_COMMIT \
  > /tmp/replay.json
```

Each sender creates one real core session and encrypts five distinct public test
messages. Inspector forwards the exact generated records to the other core. The
receiver adapter creates one session for the complete action batch; every attempt
reaches that same core instance. The adapter implements no replay cache, ordering
policy or synthetic closed-state rejection.

| Action | Expected result |
|---|---|
| Open record 0 | Recover `a` |
| Open record 0 again | Reject duplicate |
| Alter the authentication bytes of record 1 | Reject tampering |
| Open intact record 1 | Recover `b`; failed authentication did not consume it |
| Open record 3 before record 2 | Recover `d` |
| Open record 2 | Recover `c` within the receive window |
| Open record 3 again | Reject duplicate |
| Close the receiver through its real core API | Successful close |
| Open previously unseen record 4 | Reject after close |

A separate fresh receiver first recovers `e` from record 4. This positive control
proves that the post-close rejection is not masked by a previously consumed or
invalid record. The control result is retained separately and a failed control
prevents the trial from passing. The four producer calls and four controls are not
added to the 36 action count.

The new adapter operations are `legacy.session.export-sequence` and
`legacy.session.receive-sequence`, carried through the existing bounded schema1
process transport. State persists inside one explicit batch; this is not a new
schema2 host or virtual-clock binding. Export accepts at most 16 messages of 512
bytes; receive accepts at most 32 actions with records no larger than 2048 bytes.
Only caller-controlled public test seeds and disposable sessions are used. Batch
requests contain actions and input records, never expected verdicts.

Malformed inputs and process errors remain errors. Unsupported batch operations
leave their individual actions NOT_RUN. Missing, reordered or mismatched observed
actions cannot be promoted to PASS. The report records the complete producer,
fresh-control and receiver requests, hashes, observations, expected outputs,
per-action statuses, executable identities, revisions and runtime. Exit codes retain
0 for the listed checks passing, 1 for observed failure, 2 for configuration error
and 3 for incomplete support. `conformance` remains `NOT_ESTABLISHED` in every case.

Raw evidence is in `docs/evidence/deployment/replay.json`; exact build source and
runner hashes are recorded in `replay-provenance.json`. The new evidence is linked
separately in the integrated deployment report. Existing primitive counts, frozen
386-case planning status and previous stateless exchange reports are preserved.

```sh
python3 scripts/check_replay_evidence.py
python3 scripts/test_replay_inspection.py
python3 scripts/test_sequence_adapters.py /path/to/go-adapter /path/to/rust-adapter
```

CI checks archived identity, complete direction/action membership, byte forwarding,
positive controls and false verdicts, alongside Go orchestration tests. It does not
pretend to rerun the real cores on the CI runner. Core implementation and expectations
remain separate; matching legacy implementations do not prove the revised protocol.

Remaining work: transcript-bound API, complete HPKE/HTTP/WS exchange, virtual-clock
expiry and recovery, close-versus-receive races, and a pinned host
with a trustworthy external witness for the eight prepared bypass probes.

Concurrent duplicate/distinct/invalid-record delivery is now covered by the separate [bounded concurrency run](concurrent-inspection.md).
