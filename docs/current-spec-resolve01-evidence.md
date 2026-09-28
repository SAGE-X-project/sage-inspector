# Current-spec DID document projection

RESOLVE-01 defines the `application/did+json` document projected from a
validated Registry record. The [fixed scenarios](../vectors/0.10.0/resolve01-scenarios.json)
cover exact active-record projection, a fabricated authentication reference,
a missing document ID, and a public key coordinate that differs from the
authenticated record. Independent controls reject `JsonWebKey` in place of
`JsonWebKey2020`, a JSON-LD context, a private JWK member, and a wrong curve;
created and deactivated records retain services but have empty verification
methods and relationships.

The active record is synthetic: it is derived from a pinned independent
Registry fixture by changing its state. The checker verifies structural and
byte-level projection rules; it does not reverify record proofs, source
freshness, EC point handling, or interoperability with an independent DID
consumer. These fixtures bind only part of RESOLVE-01.

The [preserved Go/Rust run](evidence/current-spec/resolve01/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`c2a69c6e319e6428d9ac4a9334af23c94c809ce6`. Reassess 225 runtime
observations per core with
`python3 -B scripts/check_current_spec_resolve01_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all four document
verification operations. Full RESOLVE-01 conformance remains
`NOT_ESTABLISHED`. Across all 481 cases, Go has 18 `FAIL`, 174
`UNSUPPORTED`, 33 `PARTIAL`, and 256 `NOT_RUN`; Rust has 12 `FAIL`, 173
`UNSUPPORTED`, 40 `PARTIAL`, and 256 `NOT_RUN`.
