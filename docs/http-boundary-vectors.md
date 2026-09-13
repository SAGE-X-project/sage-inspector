# HTTP and envelope boundary fixtures

The Inspector now has 69 deterministic cryptographic-boundary cases and 24
executable inner-envelope primitive projections, supplementing the existing 41
HTTP cases. This closes the missing fixture work, **not the actual core boundary
binding**. INS-04 remains open until that binding produces real observations.
No core implementation was modified and no unsupported result counts as PASS.

## Evidence

| Suite | Independent fixture audit | Go core | Rust core |
|---|---|---|---|
| `http-boundaries.json` | 15 positive, 54 negative; expected rejection causes checked | 69 UNSUPPORTED, INCOMPLETE | 69 UNSUPPORTED, INCOMPLETE |
| `http-envelope-primitives.json` | 11 ECMAScript JCS values, 13 Node/OpenSSL signature checks | 24 PASS | 24 PASS |

Reports: [Go boundaries](evidence/http-boundaries-go.json),
[Rust boundaries](evidence/http-boundaries-rust.json),
[Go primitives](evidence/http-envelope-primitives-go.json),
[Rust primitives](evidence/http-envelope-primitives-rust.json).
The source revisions still match [the source lock](evidence/core-source-lock.json).
These are unsigned local measurements, not attestations. Runner version is `dev`;
reports pin suite and executable hashes and the observed runtime.

The primitive suite invokes existing core JCS and signature APIs. It deliberately
includes valid signatures over responses with invalid request hashes: passing a
signature check cannot establish request binding. Whole-boundary results remain
UNSUPPORTED even though these primitive checks pass.

## Boundary operation contract

`sage.http.verify` receives schema1 input with `request_hex`, `response_hex`,
`public_key_hex`, `body_repeat: 1`, integer `now_unix`, boolean `clock_trusted`,
`expected_target`, `expected_recipient`, and `trusted_keys` mapping explicit key URLs
to public Ed25519 key bytes. The mapping is an isolated, already-authorized key
observation supplied by the test harness, not an actual blockchain query. Each case
starts with fresh replay state. The request is the original sent request when
checking a response. An absent original request must fail.

Optional `request_padding` and `response_padding` specify a compact body recipe:
replace the final single ASCII space in the corresponding decoded wire bytes with
exactly that many ASCII spaces (1..16777217). Expand before handing bytes to the
subject boundary. The stored Content-Length, digest and signature already describe
the expanded body. No timestamp rewriting, re-signing, age disabling or replacement
of missing subject verification logic is permitted. [Proofs](evidence/http-boundary-proofs.json)
pin hashes of the expanded bytes. Wire fixture files remain below the 4MiB loader
limit while testing both request and response bodies at 16MiB and 16MiB+1.

The measured boundary is HTTP framing, profile policy and envelope cryptographic
validation before application payload interpretation. ACCEPT means `{"valid":true}`
at that boundary. It does not authorize dispatch. Plain payload `{}` is opaque test
content here, not a valid HPKE handshake or an Execution Guard instruction. Actual
key resolution, HPKE/session payload processing, replay persistence, dispatch and
terminal-response state are tested in their own planned work. A full production
entry point requiring those stages cannot be treated as equivalent to this
projection without explicit test controls and evidence.

The old six reserved cases in `http-signatures.json` are retained for historical
reproduction; their limited inputs are not the new boundary contract and must not
be silently relabelled as supported boundary tests.

## Covered distinctions

- Normal requests, responses, reordered signature parameters, and JSON whitespace.
- `created = now+30` versus `now+31`; `now = expires+29` versus `expires+30`;
  lifetimes 1, 300, 0 and 301 seconds; fractional/negative timestamps;
  unavailable trusted time; response expiry while the stored request remains fresh.
- Duplicate protected fields, conflicting lengths, transfer/length conflict,
  truncated or trailing body bytes, ambiguous Host, prohibited content encoding,
  trailers and media types; header/body DID, version and optional ID mismatch.
- Missing, duplicate, unknown and wrong tag parameters; a correctly signed nonce
  that disagrees with the body.
- Request and response body limits, total field and individual signature field
  boundary pairs. Padding in valid JSON whitespace permits a valid signed envelope
  to reach the body limit without exceeding decoded payload limits.
- Complete signed request JCS hashing, inclusion of the request signature,
  exclusion of wire formatting differences, rejection of payload-only hashes,
  hash of unsigned requests, and stale hashes even with a correctly rebound outer
  response signature. Message ID, recipient, context and task mismatch are separate.
- Inner signature and payload tampering, request/response domain substitution,
  unsigned response, malformed envelope fields, and signed application failures.

Size fixtures declare a measurement convention: the total counts serialized field
lines including their terminating CRLF, excluding the start line and final empty
line. Individual field sizes count raw value octets after the fixture's single
separator SP and before CRLF, including trailing OWS. The pinned spec does not
explicitly define those counting details. Therefore exact 32KiB/8KiB conclusions
remain conditional on that convention; specification clarification is required
before using those pairs as unconditional certification criteria. The tests must
not silently strip OWS before applying the declared bound.

## Independence and integrity

[Python generator](../scripts/generate_http_boundary_vectors.py) signs inner and
outer domains with public RFC8032 TEST1 key material and hashes complete envelopes.
It imports no target or local RFC implementation. ASCII keys and integer timestamps
permit a small explicit JCS subset; the fractional timestamp rejection case uses an
exactly representable half-second. Fixed keys/nonces are unsuitable for deployment.

[Node checker](../scripts/check_http_boundaries.js) separately parses serialized
fixtures, reconstructs signature bases and JCS using ECMAScript, hashes with Node
crypto, and verifies signatures with Node/OpenSSL. It checks both the verdict and
the isolated expected rejection cause in the proof file. This is an independent
calculation path, not an independent expert review or production verifier: Python
and Node may share the OpenSSL crypto backend. It supports the fixture grammar,
not arbitrary HTTP, strict Ed25519 subgroup certification or the entire SAGE schema.

[Audit regression tests](../scripts/test_http_boundary_audit.py) confirm that changed
verdicts, evidence hashes, rejection causes, content bytes and clock boundaries fail
the audit. The root CI runs those checks and the primitive checks. The Go loader
regression also ensures the built-in reference reports every new case UNSUPPORTED;
it cannot accidentally certify these operations. Adapter execution remains a local
cross-repository measurement, not a claim that CI rebuilt either core.

## Remaining binding work and exit conditions

[Capability evidence](evidence/http-boundary-capabilities.json) identifies the actual
missing boundaries. Go `checkSignatureTimes` calls `time.Now`; Rust `check_params`
calls `SystemTime::now`. Neither selected verifier exposes fixed-clock control.
Go's existing wire schema is the legacy payload-only format, and neither inspected
core exposes the complete 0.10.0 envelope/request-hash verification path.

A clock option alone is insufficient. The respective core owner must provide the
HTTP/envelope cryptographic boundary, trusted-clock/key observation test controls,
and bounded raw-message input. Then the Inspector adapters must bind these controls
and run all positive/negative pairs without injecting the missing security checks.
A conforming result is not required to finish Inspector measurement: actual FAIL
observations are valid evidence. An unconditional UNSUPPORTED stub is not sufficient
to close that integration work. Exact field-byte counting also needs a normative
clarification before size-boundary certification.

## Reproduction

```sh
python3 scripts/generate_http_boundary_vectors.py /tmp/http-boundaries.json /tmp/http-boundary-proofs.json
cmp /tmp/http-boundaries.json vectors/0.10.0/http-boundaries.json
cmp /tmp/http-boundary-proofs.json docs/evidence/http-boundary-proofs.json
python3 scripts/generate_envelope_projections.py /tmp/http-envelope-primitives.json
cmp /tmp/http-envelope-primitives.json vectors/0.10.0/http-envelope-primitives.json
node scripts/check_http_boundaries.js vectors/0.10.0/http-boundaries.json docs/evidence/http-boundary-proofs.json
node scripts/check_jcs_literals.js vectors/0.10.0/http-envelope-primitives.json
node scripts/check_envelope_signatures.js vectors/0.10.0/http-envelope-primitives.json
python3 scripts/test_http_boundary_audit.py
make test-foundation
```

Generate reports with the existing `sage-conformance -suite ... -adapter ...
-subject ... -revision ... -report ...` contract. Boundary reports exit3 (INCOMPLETE);
primitive reports exit0. Do not combine 24 primitive PASS results with 69 unsupported
boundary results into a passing full-profile claim.
