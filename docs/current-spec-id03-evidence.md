# Current-spec named signing keys

ID-03 requires the full key URL to resolve to the exact accepted, unexpired
key in the authenticated sender's active record. The verifier must reject
unknown, revoked, and expired keys, algorithm mismatches, and unrelated
senders; it must not try another key after the named key fails. Six
revision-bound fixtures reuse independently audited registry authentication
inputs. The revoked and expired inputs each retain another accepted signing
key to test the no-fallback condition. The sender-mismatch input changes the
sender field; it does not prove that a second signer is independently
registered, so that additional boundary remains open.

The [preserved 134-case Go/Rust run](evidence/current-spec/id03/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`6954cd5cca7267ab9bb9c528fa6ce5085502f827`. Recheck the fixture,
runner, observation, and subject identities with
`python3 -B scripts/check_current_spec_id03_evidence.py`.

Neither primitive adapter exposes `sage.registry.authenticate`; all six
ID-03 cases remain `UNSUPPORTED` for each core. A separate bounded
[retained-core run](evidence/current-spec/id03/state/report.json) executed
five relevant state scenarios in both cores: selection of a named signing
key, rejection of an unknown name, and rejection after revocation, expiry,
or algorithm change. These ten matching observations use synthetic trusted
Source and Clock values and do not establish full record proof, actual
signature verification, sender binding, peer binding, or protected effects.
They are prerequisites, not parent-case passes.

Across all 481 cases, Go has 18 `FAIL`, 83 `UNSUPPORTED`, 33 `PARTIAL`, and
347 `NOT_RUN`; Rust has 12 `FAIL`, 82 `UNSUPPORTED`, 40 `PARTIAL`, and 347
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
