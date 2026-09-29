# Current-spec transport header projections

TABLE-06 defines required version and sender-DID headers and optional body
projections. The [fixed scenarios](../vectors/0.10.0/table06-scenarios.json)
cover a matching request projection, a context header/body mismatch, and an
unsigned optional header used as routing authority even though its value
matches the body. Eighteen independent controls check absent optional headers,
missing required headers or signature-field presence, body/keyid/parameter
equality, exact request covered-component order, content type, and rejection
of the removed `X-SAGE-Meta-*` projection.

These fixtures exercise a synthetic request header/body projection. They do
not parse or verify RFC 9421 signatures, recompute Content-Digest, validate a
trusted HTTP endpoint, test response request-binding, or reserve replay state.
The input's `verified-body` routing source is a model assertion, not evidence
of a completed verifier. All three runtime bindings are partial.

The [preserved Go/Rust run](evidence/current-spec/table06/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`a1fb562514fa6448dd980c7953009c5224da241b`. Reassess 268 runtime
observations per core with
`python3 -B scripts/check_current_spec_table06_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all three complete
header-binding operations. Across all 481 cases, Go has 18 `FAIL`, 217
`UNSUPPORTED`, 33 `PARTIAL`, and 213 `NOT_RUN`; Rust has 12 `FAIL`, 216
`UNSUPPORTED`, 40 `PARTIAL`, and 213 `NOT_RUN`. Conformance remains
`NOT_ESTABLISHED`.
