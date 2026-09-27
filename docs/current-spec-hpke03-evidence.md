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

The preserved Go/Rust observations and their limits are checked by
`python3 -B scripts/check_current_spec_hpke03_evidence.py`.
