# Current-spec signed intent checks

The [six fixtures](../vectors/0.10.0/exec03-intents.json) project checked
intent bytes into the pinned current spec. The positive intent has a valid
Ed25519 signature over the required domain and closed fields. The changed
argument invalidates that signature; the unknown-field intent has its own
valid signature, so rejection is not merely a signature failure. Additional
probes cover a 1 MiB plus one byte generic JSON bound, malformed nonce, and
an executor identity mismatch. The historical byte source is pinned and the
independent checker verifies the signature and isolated mutations.

These are partial cases. The size probe uses a generic JSON parser rather
than the full intent envelope. The bad nonce has a stale signature, so its
rejection does not isolate nonce-format enforcement. The identity probe
compares the intent to a configured executor but does not observe an outer
HTTP message. None observes final dispatch or protected effects.

The [archived Go and Rust runs](evidence/current-spec/exec03/) pin `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`574d853f609bdc8330230075a668c6d1da2c05ea`. Reassess 281 runtime
observations per core with
`python3 -B scripts/check_current_spec_exec03_evidence.py`.

Both cores matched the six primitive expectations. Across all 481 cases,
Go has 18 `FAIL`, 220 `UNSUPPORTED`, 43 `PARTIAL`, and 200 `NOT_RUN`;
Rust has 12 `FAIL`, 219 `UNSUPPORTED`, 50 `PARTIAL`, and 200 `NOT_RUN`.
Overall conformance remains `NOT_ESTABLISHED`.
