# Current-spec HTTP freshness and replay

MSG-05 requires strict time bounds, a canonical 16-byte nonce, one shared
acceptance transaction, denial after a repeated nonce even when a signing key
rotates, at-most-one concurrent acceptance, and 360 seconds of refusal after
lost replay state. Six revision-bound fixtures describe these conditions with
trusted synthetic time and isolated state. The vector checker pins the exact
`expires+30` and `created-(30+1)` rejection boundaries, identical replay tuple
across signing-key IDs, a two-copy race, and refusal at 359.999 seconds after
state loss. These are scoped freshness/replay expectations. They neither send
HTTP traffic nor claim a complete signed-envelope exchange.

The [durable replay report](durable-replay010.md) contains earlier actual Go
and Rust journal-process observations, including retention, duplicate denial,
clean recovery, and lost-state quarantine. Its 24 local scenarios and 20
cross-process recovery scenarios are useful implementation evidence. The
journal is called only after authentication; it cannot itself verify RFC 9421
signatures, match nonce values with a signed envelope, or establish that the
HTTP and envelope paths share one acceptance transaction. Its revisions are
historical and are not substituted for the pinned current-core observations.

The [preserved 48-case Go/Rust run](evidence/current-spec/msg05/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`3d7bd9a48b248e50e4223de87f98da5b96e184bc`. Recheck fixture relations,
historical journal provenance, runner hashes, all observations, and assessments
with `python3 -B scripts/check_current_spec_msg05_evidence.py`.

The current Go and Rust primitive adapters expose neither
`sage.http.freshness.verify` nor full `sage.http.verify`. Therefore all six
current-spec MSG-05 runtime cases remain `UNSUPPORTED` against both pinned
cores. The expected outcomes include no protected dispatch count because
the scoped operation does not dispatch. HTTP freshness, clock trust, and
zero-effect rejection still require a receiving-boundary implementation and
new runtime evidence. Overall 0.10.0 conformance remains `NOT_ESTABLISHED`.
Across all 481 cases, Go has eight `FAIL`, twenty-three `UNSUPPORTED`,
seventeen `PARTIAL`, and 433 `NOT_RUN`; Rust has two `FAIL`, twenty-three
`UNSUPPORTED`, twenty-three `PARTIAL`, and 433 `NOT_RUN`.
