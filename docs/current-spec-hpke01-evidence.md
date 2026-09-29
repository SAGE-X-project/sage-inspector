# Current-spec HPKE suite and key roles

HPKE-01 fixes one suite: Base mode, X25519/HKDF-SHA256 KEM `0x0020`,
HKDF-SHA256 KDF `0x0001`, and ChaCha20-Poly1305 AEAD `0x0003`.
The protocol uses the HPKE exporter, and the authenticated envelopes must
establish current Ed25519 signing keys while a distinct active X25519 key
is selected for the responder KEM. HPKE Base does not authenticate the sender.

Four revision-bound Inspector fixtures cover the rule. The positive case
binds RFC 9180 Appendix A.2.1's fixed Base exporter answer to the current
Go and Rust core APIs. The independent Node HPKE audit recalculates the
published anchor and the SAGE schedule. The remaining cases use a canonical
initiation from the existing 0.10.0 derivation fixtures, then isolate an
unsupported suite, a missing sender envelope signature, and a revoked
responder KEM key. Their trusted context keeps Ed25519 signing keys separate
from the responder's X25519 KEM key. The expected denial includes zero
session creation and protected dispatch; these effects are not yet observed.

The exporter operation proves only a fixed cryptographic primitive result.
It does not prove the envelope authentication, current key resolution,
suite-selection policy, fresh context, or complete session establishment.
Neither current core adapter exposes the scoped `sage.hpke.establish`
operation. Those three denial cases must remain `UNSUPPORTED` until an
authenticated handshake entry point and effect instrumentation are bound.
The fixtures contain only public deterministic test material and run locally;
they do not send network traffic.

The [preserved 56-case Go/Rust run](evidence/current-spec/hpke01/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`fdbf6d163d14b8757d6d526e81d0f31c23aa4e94`. Recheck fixture
relations, runner hashes, all observations, and assessments with
`python3 -B scripts/check_current_spec_hpke01_evidence.py`.

Both cores match the exporter answer, so HPKE-01-P is `PARTIAL` in each.
HPKE-01-N01 through N03 are `UNSUPPORTED`, with no session or dispatch
effect observation. Across all 481 cases, Go has nine `FAIL`, 29
`UNSUPPORTED`, 18 `PARTIAL`, and 425 `NOT_RUN`; Rust has two `FAIL`, 29
`UNSUPPORTED`, 25 `PARTIAL`, and 425 `NOT_RUN`. Overall conformance is
`NOT_ESTABLISHED`.
