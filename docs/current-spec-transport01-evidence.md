# Current-spec transport envelope schema

TRANSPORT-01 requires a closed JSON envelope, canonical UUIDv4, unpadded
base64url, and bounded metadata. Five bound fixtures cover a valid signed
request, an unknown top-level member, an invalid UUID variant, a padded
payload, and a 1025-byte metadata value. The valid, unknown-member, and
padded-payload envelopes are extracted from independently signed HTTP
boundary vectors. The other two use the same public test signing key. An
independent OpenSSL check confirms all five inner signatures are valid; each
negative differs from the valid unsigned envelope by only its named field.

The [preserved 159-case Go/Rust run](evidence/current-spec/transport01/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`4be582b7910a63c6334a93056db63b2dbdb272fa`. Reassess fixture, runner,
executable, and observation hashes with
`python3 -B scripts/check_current_spec_transport01_evidence.py`.

Neither primitive adapter exposes `sage.transport.envelope.verify`; all five
TRANSPORT-01 cases are `UNSUPPORTED`. The separate bounded
[signature-primitive run](evidence/current-spec/transport01/primitives/report.json)
shows that both cores accept all five as generic Ed25519 signatures, including
all four schema-invalid envelopes. This confirms only cryptographic signature
validity. It does not establish closed-schema parsing, UUID/base64url/metadata
validation, registry binding, freshness, or complete transport conformance.

Across all 481 cases, Go has 18 `FAIL`, 108 `UNSUPPORTED`, 33 `PARTIAL`, and
322 `NOT_RUN`; Rust has 12 `FAIL`, 107 `UNSUPPORTED`, 40 `PARTIAL`, and 322
`NOT_RUN`. Overall conformance remains `NOT_ESTABLISHED`.
