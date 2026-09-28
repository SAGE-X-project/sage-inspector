# Current-spec web Registry authority

REG-08 allows an optional web Registry with a configured HTTPS origin and
operator as its trust root. It does not inherit on-chain registration
assurance. A blockchain-required deployment rejects web identities. An
approved destination, authenticated TLS origin, exact well-known path,
uncached direct response, short lifetime, complete record validation, and
operation-scoped use are all required before a read can authorize work.

The [fixed scenarios](../vectors/0.10.0/reg08-scenarios.json) cover one
synthetic fresh read, a redirect to another origin, an intermediated positive
cache response, and a missing configured authority. Six controls check a
`304`, missing `no-store`, expiry at the exact end time, a response over
69,632 bytes, blockchain-required policy, and an unapproved destination.
The record starts from a pinned independent Registry fixture, with state
changed to active for the synthetic read. These checks do not perform a
network fetch, TLS authentication, operator write, tombstone retention, or
complete record proof verification.

The case map also names `REG-08-N04` as “unsupported media type.” Chapter 09
requires a three-member response object but does not specify an allowed
`Content-Type` for the web origin fetch. Chapter 10 defines media types for
the separate public resolution API. Inspector therefore records N04 as an
[explicit unresolved specification decision](../vectors/0.10.0/reg08-scenarios.json)
without inventing an expected response. It has no current-spec binding or
runtime observation and remains `NOT_RUN`. The normative decision belongs in
the planned specification review after the existing case sequence.

The [preserved Go/Rust run](evidence/current-spec/reg08/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`bd6bb8051669958a69ab7957e74b966a8e4c556b`. Reassess the 221 runtime
observations per core, fixtures, binaries, and N04 exclusion with
`python3 -B scripts/check_current_spec_reg08_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all four bound web
authority operations. Full REG-08 conformance remains `NOT_ESTABLISHED`.
Across all 481 cases, Go has 18 `FAIL`, 170 `UNSUPPORTED`, 33 `PARTIAL`, and
260 `NOT_RUN`; Rust has 12 `FAIL`, 169 `UNSUPPORTED`, 40 `PARTIAL`, and 260
`NOT_RUN`.
