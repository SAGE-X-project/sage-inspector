# Current-spec registry key selection and identity

REG-02 requires exact named, accepted, unexpired signing keys. A new
handshake chooses the accepted, unexpired `x25519` key with the first ASCII
name, and binds its full key URL to the transcript. A signing key is never a
KEM fallback. A key's material and proof remain immutable after addition.

Four [fixed public scenarios](../vectors/0.10.0/reg02-scenarios.json) cover
the earliest eligible KEM, its invalid proof despite a valid later KEM,
authentication with a revoked named Ed25519 key despite an accepted
alternative, and changed KEM material under the same name. The last scenario
compares previous and candidate records with individually valid proofs and a
new record version; validating the candidate alone cannot reveal the
historical identity change. Three controls check no KEM, a revoked earliest
KEM, and an expired earliest KEM. The independent checker verifies proof
signatures and source-vector identity. It pins the current Registry and
algorithm chapter hashes because the older Inspector snapshot is not the
current normative text.

The [preserved 194-case Go/Rust run](evidence/current-spec/reg02/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`ef0729acc4238aabcc4eda06ea65e8f5b300eaec`. Reassess fixture, runner,
binary, and observation hashes with
`python3 -B scripts/check_current_spec_reg02_evidence.py`.

Neither current core primitive adapter exposes Registry KEM selection,
authentication, or key-transition validation. All four bound cases are
`UNSUPPORTED`. A separate [bounded signature run](evidence/current-spec/reg02/primitives/report.json)
shows both cores accept the earliest and later KEM proofs, reject the damaged
earliest proof, and accept the isolated proofs of a revoked signer and a
newly substituted KEM. Generic Ed25519 verification cannot enforce Registry
state, key immutability, exact-key selection, full key URL binding, or
transcript binding. Full REG-02 conformance remains `NOT_ESTABLISHED`.

Across all 481 cases, Go has 18 `FAIL`, 143 `UNSUPPORTED`, 33 `PARTIAL`, and
287 `NOT_RUN`; Rust has 12 `FAIL`, 142 `UNSUPPORTED`, 40 `PARTIAL`, and 287
`NOT_RUN`.
