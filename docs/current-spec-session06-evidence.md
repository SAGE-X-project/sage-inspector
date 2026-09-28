# Current-spec session closure and recovery

SESSION-06 closes a session after expiry, restart, participant or key
revocation, failed current registry validation, or explicit local closure.
No restored state may reset counters. Recovery requires a fresh authenticated
handshake, and errors must not release plaintext or reuse retired keys.

Six revision-bound fixtures cover fresh recovery after closure, a revoked
key, unavailable registry state, an expired key, restored counters, and
plaintext fallback. The fixture checker ties each case to the independently
audited closure, restart, or registry scenario and to the pinned normative
SESSION-06 text. The closure scenario establishes the old session's rejection
boundary; it does not by itself establish a new authenticated handshake.

The [preserved 118-case primitive run](evidence/current-spec/session06/)
pins `sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`,
Go `49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`52be3d64f0fd18c7c5a325e4c7f2b4ce3e17854c`. Both primitive adapters
return `UNSUPPORTED` for all six protocol operations.

A [separate stateful record run](evidence/current-spec/session06/state/report.json)
uses pinned Go and Rust core binaries. Each accepts an authenticated record,
closes the record session, and then rejects both a valid next record and a
new send without returning plaintext or a ciphertext. The retained response
and effect counters support `PARTIAL` record-layer evidence for N05. This
does not prove transport-level fallback prevention, key erasure from memory,
or zero protected application effects. The other five cases remain
`UNSUPPORTED` because the current record binaries cannot observe fresh
handshake admission, live registry decisions, trusted expiry, or restart
state policy. No restored-counter probe is used as a substitute for a
protocol-owned restart boundary.

Recheck the fixture relations, runner hashes, retained responses, and
assessments with `python3 -B scripts/check_current_spec_session06_evidence.py`.
The 481-case primitive reports have Go 11 `FAIL`, 74 `UNSUPPORTED`, 33
`PARTIAL`, and 363 `NOT_RUN`; Rust has five `FAIL`, 73 `UNSUPPORTED`, 40
`PARTIAL`, and 363 `NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
