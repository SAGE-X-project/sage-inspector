# Current-spec HTTP DID resolution binding

RESOLVE-05 defines an optional read-only HTTP binding with an explicit
protocol version, accepted representation, uncached response, and public
problem details. The [fixed scenarios](../vectors/0.10.0/resolve05-scenarios.json)
cover a successful three-member resolution envelope, an unregistered media
type, a cross-authority redirect, a response one byte above the 262,144-byte
limit, and reuse of a positive cache entry. The size case models trailing
JSON whitespace by byte count; it does not transmit a large payload.

Independent controls cover path decoding exactly once, query and extra-path
rejection, version headers, `no-store`, a document-only inspection response,
and refusal to use that bare document for authentication. Nine problem-detail
fixtures pin every local code to its exact type URI, title, and HTTP/body
status. Further controls reject mismatched fields, wrong media type, and a
partial document in an error body.

The fixtures use a synthetic HTTP exchange and the pinned RESOLVE-02
observation. They do not perform live TLS or Registry authentication. The
listed problem-type URI endpoints have not been checked for publication and
no independent RFC 9457 consumer has been tested. The suite records that
publication status as `NOT_VERIFIED`; generic problem-detail interoperability
is not claimed. These are partial RESOLVE-05 bindings.

The [preserved Go/Rust run](evidence/current-spec/resolve05/) pins `sage-spec`
revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`06bb0577e4273d833081408d4d3bfa94f6a0463f`. Reassess 246 runtime
observations per core with
`python3 -B scripts/check_current_spec_resolve05_evidence.py`.

Both core primitive adapters return `UNSUPPORTED` for all five HTTP
resolution operations. Full RESOLVE-05 conformance remains
`NOT_ESTABLISHED`. Across all 481 cases, Go has 18 `FAIL`, 195
`UNSUPPORTED`, 33 `PARTIAL`, and 235 `NOT_RUN`; Rust has 12 `FAIL`, 194
`UNSUPPORTED`, 40 `PARTIAL`, and 235 `NOT_RUN`.
