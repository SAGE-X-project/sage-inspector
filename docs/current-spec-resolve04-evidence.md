# Current-spec exact DID key dereference

RESOLVE-04 requires a fresh resolution followed by exact DID URL and key
name equality. The [fixed scenarios](../vectors/0.10.0/resolve04-scenarios.json)
cover one accepted X25519 agreement key, a missing fragment, an unknown key,
a retained revoked key, a service fragment presented as a key, and use of an
agreement key for the authentication relationship. The negative runtime
expectation is a generic rejection; the independent checker records local
causes without exposing key state through a public authentication response.

Six controls check a valid signing-key authentication lookup, expiry at the
trusted clock, an unexpected peer DID, percent-encoded fragments, a stale
observation, and an inactive record. Unknown fragments do not trigger a
search over other record keys. The Registry input is a pinned synthetic web
observation. The checker enforces its bounded trust fields and record shape,
but it does not perform live TLS, Registry proof revalidation, signature
verification, or public error-collapsing integration. These are partial
RESOLVE-04 bindings.

The [preserved Go/Rust run](evidence/current-spec/resolve04/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`c39765932e2d8a39494f45b31deb5ee533ff075b`. Reassess 241 runtime
observations per core with
`python3 -B scripts/check_current_spec_resolve04_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all six dereference
operations. Full RESOLVE-04 conformance remains `NOT_ESTABLISHED`. Across all
481 cases, Go has 18 `FAIL`, 190 `UNSUPPORTED`, 33 `PARTIAL`, and 240
`NOT_RUN`; Rust has 12 `FAIL`, 189 `UNSUPPORTED`, 40 `PARTIAL`, and 240
`NOT_RUN`.
