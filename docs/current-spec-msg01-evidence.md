# Current-spec HTTP signature boundary

The five MSG-01 fixtures use a signed HTTP request with an independently
verified Ed25519 `sig1`, a body digest checked from the literal `{}` bytes,
and an independently constructed RFC 9421 signature base. Four cases each
change one condition: an extra `sig2` label, a duplicate `created` parameter,
an unknown but validly signed `extra` parameter, or malformed digest encoding.
The fixture checker verifies the signed control and exact changes with
OpenSSL. No signing private key is retained in the fixtures.

The [preserved 25-case Go/Rust run](evidence/current-spec/msg01/) assesses
the same pinned `sage-spec` revision (`5bcf511e604579afa63f434013447f44b6858828`)
against Go `49379baadc6baec9ca8b4bb7d15bf43d65144bd7` and Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`. The runner revision is
`5ab5403f065d21eab87fe73e3ee332fdc5a3b557`. Run
`python3 -B scripts/check_current_spec_msg01_evidence.py` to recheck fixture
provenance, runner hashes, observations, and assessments.

The Go `rfc9421.base` primitive omits the `tag` signature parameter from
`MSG-01-P`'s derived base, so the bounded positive observation is `FAIL`.
Rust includes `tag` and matches the base and digest, yielding `PARTIAL`.
Both cores reject malformed `Content-Digest` encoding in `MSG-01-N04`, also
`PARTIAL`. Neither adapter exposes a complete `sage.http.verify` entry point;
`MSG-01-N01`, `N02`, and `N03` are `UNSUPPORTED` in both subjects. Their
effects and full SAGE HTTP processing are not established by these primitive
checks. The generic RFC 8941 parameter parser's handling of duplicate keys
does not itself establish a SAGE profile failure; N02 must be checked by the
full SAGE verifier. The unresolved private HTTP algorithm issue in the
standards audit remains outside this Ed25519 fixture.

Across all 481 current cases, Go has five `FAIL`, seven `UNSUPPORTED`,
thirteen `PARTIAL`, and 456 `NOT_RUN`. Rust has two `FAIL`, seven
`UNSUPPORTED`, sixteen `PARTIAL`, and 456 `NOT_RUN`. Neither result establishes
overall 0.10.0 conformance. The next step is to expose complete, versioned
SAGE card and HTTP verification in the core adapters and observe protected
effects before promoting these cases.
