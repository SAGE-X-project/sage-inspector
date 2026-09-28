# Current-spec replay and reordering

SESSION-05 permits an unseen authenticated record to arrive out of order,
rejects duplicates, and requires failed authentication to leave replay state
unchanged. Concurrent copies must have at most one acceptance. A 1024-slot
receive window and the fixed per-direction message cap both apply.

Five revision-bound fixtures cover reordered acceptance, concurrent copies,
a bad tag followed by a valid record at the same sequence, a duplicate, and
an out-of-window value. Their inputs and expectations are checked against the
independent session scenarios and pinned normative text. The independent Node
audit checks those scenarios without claiming a core result.

The [preserved 112-case primitive run](evidence/current-spec/session05/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`36bf33fd115994b63137f5c3daa23ada18e9acee`. Its primitive adapters
return `UNSUPPORTED` for all five stateful operations.

A [separate retained-record run](evidence/current-spec/session05/state/report.json)
uses actual Go and Rust stateful core binaries, pinned by executable hash and
Inspector runner revision `6b27f9861921dcca2cb5a5e2e47796f962a2a57a`.
Both cores accept independently computed authenticated records at sequences
999, 0, and 256, then reject the duplicate zero. Both reject a bad tag at
999 and subsequently accept the valid 999 record. Accepted plaintext and
core-open counters match independent record vectors. These three cases have
`PARTIAL` record-layer evidence in the separate run; they do not become
`PASS` in the case-level assessment. The stateful binaries do not observe
signed envelopes, protected dispatch, or application effect ordering.

The concurrent-copy case remains `UNSUPPORTED`: a sequential record stream
cannot establish atomic acceptance under a race. The out-of-window fixture
also remains `UNSUPPORTED`. Sequence 1024 would be needed to move the
1024-slot window beyond sequence zero, but the profile's 1000-record cap
rejects it first. This case cannot isolate the window rule within a valid
0.10.0 session. The fixture records that boundary for the planned later
specification review; it does not treat a cap rejection as proof of bitmap
behavior.

Recheck the fixture relations, both runner hashes, retained responses, and
assessments with `python3 -B scripts/check_current_spec_session05_evidence.py`.
The 481-case primitive reports have Go 11 `FAIL`, 68 `UNSUPPORTED`, 33
`PARTIAL`, and 369 `NOT_RUN`; Rust has five `FAIL`, 67 `UNSUPPORTED`, 40
`PARTIAL`, and 369 `NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
