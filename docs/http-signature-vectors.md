# HTTP signature and content validation evidence

SAGE0.10.0 Inspector expansion: 41 fixed cases using the schema1 primitive tooling
profile. The SAGE/Rust core and user-designated rfc9421 repository were not modified.
This delivery implements the reproducible base, body and archived-verification
checks. INS-04 remains partially complete: deterministic full HTTP boundary tests
and the transport-envelope request hash still need subject bindings.

## Operations and claim boundaries

| Operation | Actual subject call | Claim |
|---|---|---|
| `rfc9421.base` | Go ParseSignatureInput + Canonicalizer; Rust dictionary parser + canonicalize/build_signature_base | Exact ordered signature-base bytes, including tag and stored request components |
| `sage.content-digest` | Go BodyIntegrityValidator; Rust verify_content_digest | SAGE digest/body restrictions at these selected APIs only |
| `rfc9421.archived.verify` | Go HTTPVerifier.VerifyRequest/VerifyResponse; Rust HttpVerifier.verify_request_with/verify_response | Cryptographic signature, covered body, authority and request binding for archived fixtures |
| `sage.http.verify` | No suitable deterministic clock/full boundary binding | UNSUPPORTED; never replaced by the archival operation |

Archived fixtures explicitly omit expiry/tag and use a fixed historic creation time.
The adapters disable only the age check using the core's documented archival option;
they do not rewrite timestamps, re-sign messages, mock the machine clock or claim
production freshness conformance. Required request/response component lists and
request authority are configured through the existing core policy options.
These are intentionally RFC mechanism fixtures, not valid full SAGE exchanges.

Neither a valid signature nor digest is an execution authorization. No dispatch,
ledger, resolver, response consumption or whole-host safety result is inferred.
In particular, Rust's digest helper is a byte-array primitive; its acceptance of an
oversized body shows the missing bound at that API, not a demonstrated bypass of
an untested complete server stack.

## Independent inputs

[Generator](../scripts/generate_http_vectors.py) constructs explicit ordered bases
from RFC9421 sections2.3..2.5 and the pinned SAGE HTTP profile. It uses Python hashlib
for Content-Digest and cryptography/OpenSSL with the public RFC8032 test seed to
sign fixed bytes. It never imports or invokes SAGE or the local RFC implementation.
[Checker](../scripts/check_http_fixtures.py) separately reconstructs 12 positive
bases/digests/signatures from the serialized wire bytes, rather than reusing the
construction routine. This is fixture cross-checking, not an independent expert audit.

[Fixtures](../vectors/0.10.0/http-signatures.json) contain hexadecimal raw HTTP1.1
requests/responses. For the16MiB size boundary, a one-byte body is repeated by an
explicit bounded `body_repeat` recipe. Its Content-Length/digest describe the fully
expanded bytes. This avoids violating Inspector's4MiB fixture-document limit.
[Wire hashes](evidence/http-wire-hashes.json) record the expanded request and response
byte counts and SHA-256. These are source audit hashes, not target attestation.

Coverage includes request and response bases, preserved parameter order and tag,
escaped target URI, `;req`, missing stored request, tampered request Signature/target/
digest, response status/body tampering, unsigned messages, ignored untrusted
Forwarded headers, raw whitespace in content, noncanonical digest encoding,
extra/duplicate digest members and field instances, and16MiB/16MiB+1 bodies.

Six reserved boundary cases cover duplicate Content-Type, inconsistent length,
Transfer-Encoding with Content-Length, fields exceeding32KiB, expiry and wrong tag.
Their `now_unix` input specifies the intended fixed clock, but neither adapter can
inject it into the selected core API. Both return UNSUPPORTED for all six.
They remain planned rejection scenarios, not independently confirmed boundary tests.
A positive full boundary fixture, exact32KiB boundary, signature-field8KiB limits,
complete envelope verification and replay/failure-side-effect evidence remain open.

## Results

| Subject revision | PASS | FAIL | UNSUPPORTED | Overall |
|---|---:|---:|---:|---|
| Go c7709b7486e0da94336edc0931fddd87f6a45343 |27|8|6|FAIL|
| Rust206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2 |31|4|6|FAIL|

[Go evidence](evidence/http-go.json), [Rust evidence](evidence/http-rust.json).
Both archived request/response positive controls pass. Go changes received parameter
order and omits tag from reconstructed bases; this also rejects a valid reordered
archived signature. Go also accepts an attacker-added tag on an otherwise unchanged
archived signature, while Rust rejects that mutation. Both digest API paths accept additional/duplicate digest members
and duplicate field instances. Rust's digest path additionally accepts16MiB+1.
Core errors and mismatched outputs are retained rather than normalized by adapters.
A rejection case passing alone does not identify its cause or prove a whole rule.

The [existing core source lock](evidence/core-source-lock.json) was rechecked against
both checkouts. Reports include rebuilt executable hashes. Rust adds pinned httparse
for raw header parsing and preserves duplicate fields in the HTTP HeaderMap; Go uses
net/http.ReadRequest/ReadResponse. These different boundaries are explicitly part
of the adapter composition. The Rust bridge does not implement transfer decoding
or a full HTTP framing boundary. Framing cases therefore use the unsupported full
boundary operation, not the archival operation. No arbitrary malformed wire support
is claimed for the fixture bridges.

## Designated reference repository

[Provenance](evidence/http-provenance.json) pins the current rfc9421 revision and
consulted English text/parser/builder hashes. The English text matches the earlier
spec assessment; code hashes/revision have changed since that assessment. Inspection
still shows the legacy request-target construction and omitted signature-params in
the builder. It informs regression scenarios but is not used to generate expectations.
No fresh build or full conformance claim is made for that repository in this delivery.
Official [RFC9421](https://www.rfc-editor.org/rfc/rfc9421.html) and
[RFC9530](https://www.rfc-editor.org/rfc/rfc9530.html), plus the pinned SAGE profile,
remain the normative sources.

## Reproduction and checks

```sh
python3 scripts/generate_http_vectors.py /tmp/http-signatures.json
cmp /tmp/http-signatures.json vectors/0.10.0/http-signatures.json
python3 scripts/check_http_fixtures.py vectors/0.10.0/http-signatures.json
```

Build adapters as described in [core-adapters.md](core-adapters.md), then run
sage-conformance with `-suite vectors/0.10.0/http-signatures.json`, the explicit
adapter/subject/revision and a report path. Both current subjects return exit1
because real mismatches are recorded. `test_http_adapters.py` takes both executable
paths and checks invalid hex, repeat bounds, absent signature input and unsupported
boundary reporting. Five checks per adapter pass. Fixture regeneration is byte-exact;
existing conformance tests, race checks and vet are also required before merge.
The original26 vectors, JCS/signature suite and386-case planning status are unchanged.

Follow-up: [HTTP/envelope boundary fixtures](http-boundary-vectors.md) provide the missing positive controls, deterministic timing and size pairs, and signed-request hash substitutions. The new actual-core primitive observations are separate from the still-unsupported full boundary.
