# Current-spec fresh DID resolution

RESOLVE-02 requires one authorized fresh Registry observation, validation of
the complete record, and a three-member resolution result. The
[fixed scenarios](../vectors/0.10.0/resolve02-scenarios.json) cover a current
configured web observation, an absent identifier, a malformed inactive record,
expiry at the trusted clock, an unauthenticated TLS origin, and reuse of an
intermediated positive cache. Supplemental controls verify that a valid
deactivated record still resolves for inspection, while missing state, a
different record ID, a peer-supplied resolver URL, an invalid version, and a
rollback below the locally observed version fail closed.

The starting record is the pinned synthetic REG-08 web fixture. The checker
audits record shape, proof presence and signer references, version ordering,
projection shape, and the specified observation fields. It does not verify
cryptographic proofs or live TLS identity, contact a Registry, establish
operator provenance, or test on-chain finality. The injected observation is
not evidence that an arbitrary third-party resolver is trusted. These
fixtures are partial RESOLVE-02 bindings.

The [preserved Go/Rust run](evidence/current-spec/resolve02/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`b04859ff58b90d0b4f97269778d8dd0e452702b0`. Reassess 231 runtime
observations per core with
`python3 -B scripts/check_current_spec_resolve02_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all six resolution
operations. Full RESOLVE-02 conformance remains `NOT_ESTABLISHED`. Across all
481 cases, Go has 18 `FAIL`, 180 `UNSUPPORTED`, 33 `PARTIAL`, and 250
`NOT_RUN`; Rust has 12 `FAIL`, 179 `UNSUPPORTED`, 40 `PARTIAL`, and 250
`NOT_RUN`.
