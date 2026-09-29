# Current-spec signature algorithm identifiers

TABLE-02 registers three exact signature algorithm names: mandatory `ed25519`,
optional `sage-secp256k1-keccak256`, and optional `ecdsa-p256-sha256`. The
[fixed scenarios](../vectors/0.10.0/table02-scenarios.json) select the exact
SAGE-local secp256k1/Keccak-256 suite, reject the obsolete `es256k` name, and
reject an inferred JOSE `ES256K` alias. Twelve independent controls check
mandatory Ed25519 support, optional-suite fail-closed behavior, P-256 support
gating, key roles, exact digest and name matching, signature length, and private
algorithm names on an external wire.

These fixtures exercise synthetic algorithm dispatch only. They do not generate
or verify signatures, establish that a deployed implementation supports the
optional secp256k1 suite, or establish complete TABLE-02 conformance. All three
runtime bindings are partial.

The [preserved Go/Rust run](evidence/current-spec/table02/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`b8861d893b8ec9ddc94a4082bd7506246ae4222d`. Reassess 253 runtime
observations per core with
`python3 -B scripts/check_current_spec_table02_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all three algorithm
selection operations. Across all 481 cases, Go has 18 `FAIL`, 202
`UNSUPPORTED`, 33 `PARTIAL`, and 228 `NOT_RUN`; Rust has 12 `FAIL`, 201
`UNSUPPORTED`, 40 `PARTIAL`, and 228 `NOT_RUN`. Conformance remains
`NOT_ESTABLISHED`.
