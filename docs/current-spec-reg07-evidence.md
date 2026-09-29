# Current-spec reserved Solana profile

REG-07 reserves `solana` for a future profile. A 0.10.0 resolver must return
`id.unknown-kind`; it must not claim that transaction ordering alone protects
registration, or accept a Solana record as conformant. A future profile needs
its own complete deployment binding and independent cases.

The [two fixed cases](../vectors/0.10.0/reg07-scenarios.json) require the
exact public error for resolution and for an attempted conformant record
admission. Three separate primitive controls use the same reserved DID and
current web and eip155 DID forms. They are parser observations, not complete
resolver or Registry profile tests.

The [preserved Go/Rust run](evidence/current-spec/reg07/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`a5de8984ec52dc3986f59624d0592f5a0c012198`. Reassess the 217 runtime
observations per core, fixtures, binaries, and the isolated parser run with
`python3 -B scripts/check_current_spec_reg07_evidence.py`.

Both primitive adapters return `UNSUPPORTED` for the complete resolver and
profile-admission operations, so neither current-spec case is established.
In the [isolated DID parser run](evidence/current-spec/reg07/primitives/report.json),
both cores `ACCEPT` the reserved Solana DID and `REJECT` the current web and
eip155 controls. This exposes a legacy syntax boundary that needs replacement
or enforcement before full 0.10.0 resolution; it does not prove the complete
resolver accepts a Solana record. The primitive also does not expose the
required `id.unknown-kind` error. Overall REG-07 conformance remains
`NOT_ESTABLISHED`.

Across all 481 cases, Go has 18 `FAIL`, 166 `UNSUPPORTED`, 33 `PARTIAL`, and
264 `NOT_RUN`; Rust has 12 `FAIL`, 165 `UNSUPPORTED`, 40 `PARTIAL`, and 264
`NOT_RUN`.
