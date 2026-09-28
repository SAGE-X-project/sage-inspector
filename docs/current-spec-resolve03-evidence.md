# Current-spec DID resolution metadata

RESOLVE-03 requires metadata from the same current Registry state used to
produce the DID document. A successful resolution of a `created` or
`deactivated` record is available for inspection but cannot authorize a
protected operation. The [fixed scenarios](../vectors/0.10.0/resolve03-scenarios.json)
cover active, created, and deactivated state, reuse of a cached active result
after deactivation, an unapproved canonical ID alias, and an incorrect
`contentType`. Eight controls check observation fields, missing state, a false
deactivation flag, source bounds, source freshness, and premature
authorization.

The fixtures use synthetic current observations derived from a pinned web
Registry record. `DEFER` for an active record means that separate signature,
key, policy, and freshness checks must decide authorization; it is not an
allow decision. The checker verifies exact metadata, projected document
shape, the 262,144-byte response bound, and the inactive authorization gate.
It does not authenticate a live Registry, reverify key proofs, or execute a
protected dispatch. These are partial RESOLVE-03 bindings.

The [preserved Go/Rust run](evidence/current-spec/resolve03/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`b93a6b410dd31a61d0db15645adaff803e258a5c`. Reassess 235 runtime
observations per core with
`python3 -B scripts/check_current_spec_resolve03_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all four metadata
operations. Full RESOLVE-03 conformance remains `NOT_ESTABLISHED`. Across all
481 cases, Go has 18 `FAIL`, 184 `UNSUPPORTED`, 33 `PARTIAL`, and 246
`NOT_RUN`; Rust has 12 `FAIL`, 183 `UNSUPPORTED`, 40 `PARTIAL`, and 246
`NOT_RUN`.
