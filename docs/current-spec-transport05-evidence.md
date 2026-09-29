# Current-spec HTTP dual-signature binding

TRANSPORT-05 requires a verified HTTP signature and a verified body signature
in one acceptance transaction. The signed HTTP keyid, creation and expiry
times, and nonce must equal the body values. Required DID/version headers and
any optional ID projection must match the body; routing and authorization use
the verified body fields. A failed check must neither reserve replay state nor
dispatch an application request.

Nine [fixed local HTTP variants](../vectors/0.10.0/transport05-scenarios.json)
cover the valid request, a matching optional ID header, four independently
re-signed nonce/time/keyid mismatches, missing outer and inner signatures, and
an unsigned optional ID header that disagrees with the signed body. The
independent unit audit checks exact body digests, both signatures when present,
the isolated mismatch in each variant, and the joint accept/reject expectation.
It sends no requests and does not establish core replay or dispatch effects.

The [preserved 180-case Go/Rust run](evidence/current-spec/transport05/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`e17e82226f9e59c4142ab484e22bd78533bc42aa`. Reassess fixture, runner,
binary, and observation hashes with
`python3 -B scripts/check_current_spec_transport05_evidence.py`.

Neither core primitive adapter exposes `sage.transport.http.receive`; all four
TRANSPORT-05 representative runtime cases are `UNSUPPORTED`. A separate
[bounded local primitive run](evidence/current-spec/transport05/primitives/report.json)
shows both cores accept the 16 *present* valid Ed25519 signatures. This is
expected even for messages whose HTTP parameters or unsigned projection
disagree with the body: generic signature verification cannot decide the
joint binding. The two absent signatures were not submitted as signature
primitives. Integrated equality checks, authoritative body routing, atomic
replay reservation, and dispatch behavior remain unverified. Full
TRANSPORT-05 conformance is `NOT_ESTABLISHED`.

Across all 481 cases, Go has 18 `FAIL`, 129 `UNSUPPORTED`, 33 `PARTIAL`, and
301 `NOT_RUN`; Rust has 12 `FAIL`, 128 `UNSUPPORTED`, 40 `PARTIAL`, and 301
`NOT_RUN`.
