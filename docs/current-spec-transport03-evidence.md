# Current-spec response and request binding

TRANSPORT-03 requires a terminal response to match the retained, complete
signed request. Seven bound fixtures cover a matching pair, wrong request
hash, plaintext response to a session request, wrong response session role,
second terminal acceptance, `success=false` without `error`, and an
unsolicited response. The matching pair, wrong hash, and absent-request
response derive from the independently signed HTTP boundary vectors. All
other response signatures are re-created with the same public test key, and
the fixture audit independently verifies each request and response signature.

The [preserved 171-case Go/Rust run](evidence/current-spec/transport03/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`65b966c8ddb04133015ee27f1f994920f5546d2c`. Reassess fixture, runner,
executable, and observation hashes with
`python3 -B scripts/check_current_spec_transport03_evidence.py`.

Neither core primitive adapter exposes `sage.transport.response.verify`; all
seven TRANSPORT-03 cases are `UNSUPPORTED`. The separate bounded
[signature-primitive run](evidence/current-spec/transport03/primitives/report.json)
shows both cores accept every response as a generic Ed25519 signature. That
does not verify the stored request hash, session mode or role, terminal state,
required error code, or presence of a retained request. The session cases
use isolated envelope metadata and are not complete AEAD record exchanges;
the fixed plain payload is likewise not a complete chapter 04 handshake.
Full TRANSPORT-03 conformance remains unestablished.

Across all 481 cases, Go has 18 `FAIL`, 120 `UNSUPPORTED`, 33 `PARTIAL`, and
310 `NOT_RUN`; Rust has 12 `FAIL`, 119 `UNSUPPORTED`, 40 `PARTIAL`, and 310
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
