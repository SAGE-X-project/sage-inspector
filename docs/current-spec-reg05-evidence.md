# Current-spec Registry observation freshness

REG-05 requires a fresh authoritative Registry observation at the dispatch
gate. Record state, key state, source, block identity, finality, and the
trusted monotonic clock must be evaluated together. An earlier key selection
cannot authorize a later dispatch after an observed revocation or stale
observation.

Six [fixed scenarios](../vectors/0.10.0/reg05-scenarios.json) cover the exact
five-second acceptance boundary, mixed record and key block hashes, a
latest-only unfinalized view followed by an accepted finalized view,
unestablished readiness despite a claimed finalized head, observed signing
key revocation after selection, and the same observation rejected at six
seconds. Three additional controls cover a peer resolver, an untrusted clock,
and a fresh observation after a delayed storage operation. The checker pins
these scenarios to the existing Registry source suite and the current
`sage-spec` chapter hash.

The [preserved 210-case Go/Rust run](evidence/current-spec/reg05/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`d3f2268098688e00628d79e8b6c4e6f6e7ec4326`. Reassess the fixture,
runner, binary, and observation hashes with
`python3 -B scripts/check_current_spec_reg05_evidence.py`.

Both core primitive adapters lack the complete Registry observation sequence
operation. All six current-spec case bindings are `UNSUPPORTED`. A separate
[bounded local gate run](evidence/current-spec/reg05/gate/report.json) matches
all six scenario sequences and three controls in both cores. Its trusted
Registry Source and monotonic clock are injected, and its journals are local;
it does not establish deployed chain finality or end-to-end dispatch
conformance. The unfinalized view may deny the current operation but does not
create a permanent revocation tombstone. The readiness case proves refusal
when readiness is unavailable; it does not prove detection of a malicious
trusted source that conceals the head. Full REG-05 conformance remains
`NOT_ESTABLISHED`.

Across all 481 cases, Go has 18 `FAIL`, 159 `UNSUPPORTED`, 33 `PARTIAL`, and
271 `NOT_RUN`; Rust has 12 `FAIL`, 158 `UNSUPPORTED`, 40 `PARTIAL`, and 271
`NOT_RUN`.
