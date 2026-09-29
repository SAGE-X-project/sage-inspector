# Current-spec registry kinds

TABLE-05 indexes the `eip155` and optional `web` registry kinds and reserves
`solana` without an executable 0.10.0 profile. The
[fixed scenarios](../vectors/0.10.0/table05-scenarios.json) cover selection of
an eip155 kind with a bounded synthetic deployment descriptor, refusal of
reserved `solana`, and refusal of an unregistered kind. Thirteen independent
controls check the optional web kind, blockchain-required policy, locator
normalization, configured origin/destination, and missing or mismatched
descriptor fields.

The positive descriptor is test data. Its presence does not authenticate a
deployed code hash, ABI mapping, transaction policy, finalized chain read,
TLS origin, or operator controls. The fixtures check synthetic kind selection,
not a full resolver or deployment conformance review. All three runtime
bindings are partial.

The [preserved Go/Rust run](evidence/current-spec/table05/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`e34acf16e37a7a0f9a793d2cb756d302c360bc4d`. Reassess 265 runtime
observations per core with
`python3 -B scripts/check_current_spec_table05_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all three kind-selection
operations. Across all 481 cases, Go has 18 `FAIL`, 214 `UNSUPPORTED`, 33
`PARTIAL`, and 216 `NOT_RUN`; Rust has 12 `FAIL`, 213 `UNSUPPORTED`, 40
`PARTIAL`, and 216 `NOT_RUN`. Conformance remains `NOT_ESTABLISHED`.
