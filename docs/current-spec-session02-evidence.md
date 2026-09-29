# Current-spec directional session keys and lifetime

SESSION-02 derives separate c2s and s2c record keys with a fixed generation
change at every 256 sequence numbers. The receiver rejects sequence 1000 and
the sender closes before emitting it. Absolute session age is at most one
hour, idle age at most ten minutes, and responder confirmation cannot restart
the clocks created with provisional key state.

Six revision-bound fixtures cover five SESSION-02 cases and the related
CST-05 confirmation-clock case. The positive fixture opens independently
computed records at sequences 255, 256, and 999 in both directions against
each actual core. A separate fixture opens a validly formed sequence-1000
record and expects rejection. The remaining cases bind exact absolute and
idle clock boundaries, fixed rekey configuration, and provisional
confirmation timing to independently audited state scenarios.

Record opening proves the key schedule and receiver's sequence cap only for
the tested records. It does not prove independent live counters, sender-side
closure, full envelope validation, or monotonic session lifetime. Current
primitive adapters expose no clock, policy, or provisional-state verifier,
so those cases remain `UNSUPPORTED`. The independent session audit checks
fixture expectations rather than core behavior.

The [preserved 95-case Go/Rust run](evidence/current-spec/session02/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`f3779f3e780ff44bbdd3a9ebe25d7ec862bcb849`. Recheck source relations,
runner hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_session02_evidence.py`.

Both cores open the six boundary records and reject sequence 1000. Therefore
SESSION-02-P and SESSION-02-N01 are `PARTIAL`, while the other four cases
are `UNSUPPORTED`. Across all 481 cases, Go has 11 `FAIL`, 59 `UNSUPPORTED`,
25 `PARTIAL`, and 386 `NOT_RUN`; Rust has five `FAIL`, 58 `UNSUPPORTED`,
32 `PARTIAL`, and 386 `NOT_RUN`. Overall conformance is `NOT_ESTABLISHED`.
