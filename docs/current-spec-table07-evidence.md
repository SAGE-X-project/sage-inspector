# Current-spec diagnostic disclosure boundary

TABLE-07 registers 30 local diagnostic codes. The
[fixed scenarios](../vectors/0.10.0/table07-scenarios.json) cover an internal
`sig.bad` diagnostic with one generic public authentication failure, a
test-only sensitive-field canary in the local diagnostic, and a reason-specific
public authentication response. Twelve independent controls check that four
different protected-failure codes produce the same public response and reject
unknown codes, mismatched local codes, sensitive or full-payload log fields,
and public reason, code, status, or diagnostic-header disclosure.

These fixtures exercise a synthetic application-message boundary. The exact
local log field allowlist is fixture policy, not a general logging schema.
They do not observe a real HTTP response, persistent log sink, timing oracle,
or the separate public-resolution RFC 9457 problem-detail binding. All three
runtime bindings are partial.

The [preserved Go/Rust run](evidence/current-spec/table07/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`d25fb2e1081b11aa6e24c2ec9d0a2e6bfc9fae96`. Reassess 271 runtime
observations per core with
`python3 -B scripts/check_current_spec_table07_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all three diagnostic
boundary operations. Across all 481 cases, Go has 18 `FAIL`, 220
`UNSUPPORTED`, 33 `PARTIAL`, and 210 `NOT_RUN`; Rust has 12 `FAIL`, 219
`UNSUPPORTED`, 40 `PARTIAL`, and 210 `NOT_RUN`. Conformance remains
`NOT_ESTABLISHED`.
