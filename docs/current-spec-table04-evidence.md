# Current-spec domain separation labels

TABLE-04 indexes exact ASCII domain labels and delegates each construction's
delimiters to its defining chapter. The [fixed scenarios](../vectors/0.10.0/table04-scenarios.json)
cover 18 domain byte prefixes in their assigned roles, an obsolete HPKE label,
an omitted wire-request line feed, and use of the acknowledgment label for the
combiner HKDF. Twelve independent controls check other omitted or wrong LF/NUL
delimiters, obsolete labels, a swapped transport direction, case changes,
unassigned domains, and noncanonical hex in the test representation.

These fixtures exercise synthetic domain-byte dispatch only. They do not sign
messages, derive HKDF outputs, or establish deployed cryptographic
interoperability. All four runtime bindings are partial.

The [preserved Go/Rust run](evidence/current-spec/table04/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`2d8f931efd56f373d32c0245dbcc48f45b073ee1`. Reassess 262 runtime
observations per core with
`python3 -B scripts/check_current_spec_table04_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all four complete
domain-registry operations. Across all 481 cases, Go has 18 `FAIL`, 211
`UNSUPPORTED`, 33 `PARTIAL`, and 219 `NOT_RUN`; Rust has 12 `FAIL`, 210
`UNSUPPORTED`, 40 `PARTIAL`, and 219 `NOT_RUN`. Conformance remains
`NOT_ESTABLISHED`.
