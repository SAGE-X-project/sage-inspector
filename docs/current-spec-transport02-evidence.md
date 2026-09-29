# Current-spec whole-request signature

TRANSPORT-02 signs the complete request without its `signature` member,
under the `sage-wire-request|0.10.0` newline domain. Five bound fixtures
cover a signed request with metadata, changed recipient, changed payload,
removed metadata, and a re-signed key URL belonging to another DID. The
first three negative mutations retain the original signature and isolate
signed-byte coverage. The last signature remains valid under the same public
test key, so it isolates the separate sender/key ownership requirement.

The [preserved 164-case Go/Rust run](evidence/current-spec/transport02/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`65cacb475326e251fe69b84fe5bde6f6a46cc1fe`. Reassess fixture, runner,
executable, and observation hashes with
`python3 -B scripts/check_current_spec_transport02_evidence.py`.

Neither core primitive adapter exposes `sage.transport.request.verify`; all
five TRANSPORT-02 cases are `UNSUPPORTED`. The separate bounded
[signature-primitive run](evidence/current-spec/transport02/primitives/report.json)
shows both cores accept the positive and re-signed wrong-owner key, while
rejecting the recipient, payload, and metadata mutations. This confirms
generic Ed25519 coverage of those changed bytes, but not signer ownership or
complete request admission. The fixed `plain` payload is an isolated
signature fixture; it is not a complete chapter 04 handshake. Full
TRANSPORT-02 conformance remains unestablished.

Across all 481 cases, Go has 18 `FAIL`, 113 `UNSUPPORTED`, 33 `PARTIAL`, and
317 `NOT_RUN`; Rust has 12 `FAIL`, 112 `UNSUPPORTED`, 40 `PARTIAL`, and 317
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
