# Current-spec receive processing and replay

TRANSPORT-04 requires cryptographic acceptance to reserve message ID and
nonce atomically, plus a session sequence when applicable, before any
application dispatch. Five declarative scenarios cover a valid request,
valid outer binding with an invalid inner signature, two concurrent copies,
a failed session AEAD tag, and the same signed ID with a different nonce.
The scenarios use the independently audited HTTP and session-record vectors.
The concurrent and replay cases are unit-only state expectations; they create
no network traffic or dispatch. The changed-nonce case verifies its new inner
signature but treats the second outer binding as a simulated precondition.

The [preserved 176-case Go/Rust run](evidence/current-spec/transport04/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`365054f21461e7f1501d3bf9829dd2496fe7259c`. Reassess fixture, runner,
executable, and observation hashes with
`python3 -B scripts/check_current_spec_transport04_evidence.py`.

Neither core primitive adapter exposes `sage.transport.receive.scenario`;
all five TRANSPORT-04 cases are `UNSUPPORTED`. A separate bounded local
[AEAD record run](evidence/current-spec/transport04/tag/report.json) shows
both cores reject the fixed failed-tag record. It cannot establish that the
combined receiver avoids replay reservation or dispatch on that failure.
Atomicity, persistence, and cross-adapter replay protection remain
unverified. Full TRANSPORT-04 conformance is `NOT_ESTABLISHED`.

Across all 481 cases, Go has 18 `FAIL`, 125 `UNSUPPORTED`, 33 `PARTIAL`, and
305 `NOT_RUN`; Rust has 12 `FAIL`, 124 `UNSUPPORTED`, 40 `PARTIAL`, and 305
`NOT_RUN`.
