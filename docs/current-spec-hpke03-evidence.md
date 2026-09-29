# Current-spec HPKE transcript and combiner

HPKE-03 defines transcript T as the complete initiation plus responder `ephS`
and session handle `kid`. The transcript hash salts HKDF-Extract over both
the HPKE exporter and the independent X25519 shared secret. Two labeled
HKDF-Expand calls derive the seed and acknowledgement key, and HMAC-SHA256
produces the acknowledgement tag. Either zero X25519 shared result must be
rejected; neither component alone can become the session seed.

Five revision-bound fixtures cover the selected boundaries. The positive
fixture independently recalculates canonical T, its SHA-256 hash, RFC 5869
Extract/Expand, and the acknowledgement tag before submitting the fixed
combiner input to each core. Two denial fixtures isolate a zero X25519 result
and an all-zero direct shared secret passed to the combiner. Two further
fixtures change only the transcript context or swap its ephemeral public
fields against the trusted initiation and responder state.

The positive operation exposes a seed from the core combiner but does not
prove complete authenticated handshake processing, fresh responder entropy,
or acknowledgement verification. The zero-result probes exercise bounded
cryptographic primitives. Neither core adapter exposes the full transcript
verifier, so those two denial fixtures remain `UNSUPPORTED`. All fixtures are
deterministic local test values and do not send network traffic.

The [preserved 66-case Go/Rust run](evidence/current-spec/hpke03/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`0a47a93ecf20ce4831c01539ef1300035c3de803`. Recheck fixture relations,
runner hashes, all observations, and assessments with
`python3 -B scripts/check_current_spec_hpke03_evidence.py`.

Both cores return `4b4e3976…d6541` instead of the specified seed
`a670cc6a…2a61a6`, and both accept an all-zero direct shared input at
the combiner. Rust also returns an all-zero X25519 shared result for the
zero-public-key fixture; the Go adapter does not expose direct X25519.
These are bounded `FAIL` results, not proof of a complete handshake path.
The two changed-transcript fixtures remain `UNSUPPORTED` in both cores.
Across all 481 cases, Go has 11 `FAIL`, 36 `UNSUPPORTED`, 19 `PARTIAL`,
and 415 `NOT_RUN`; Rust has five `FAIL`, 35 `UNSUPPORTED`, 26 `PARTIAL`,
and 415 `NOT_RUN`. Overall conformance is `NOT_ESTABLISHED`.
