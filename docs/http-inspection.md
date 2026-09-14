# HTTP inspection workflow

INS-04's spec-based Inspector implementation is complete. The user-directed sequence
is to prepare inspection now and refine actual Go/Rust core bindings after those
implementations exist. Inspector readiness, subject implementation support and
subject conformance are separate states; a completed inspection tool does not turn
UNSUPPORTED or FAIL observations into PASS.

## Implemented surfaces

| Required inspection | Implementation/evidence |
|---|---|
| Request/response signature bases, Content-Digest, `;req`, tampering | 41 frozen HTTP cases and existing core adapters |
| Fixed-clock timing, raw framing and body/header bounds | 69 boundary cases with 15 positive and 54 rejection expectations, independently audited |
| Inner/outer message agreement and exact signed request hash | Boundary fixtures, including correctly signed responses with incorrect request hashes |
| Inner JCS/signature mechanisms and domain separation | 24 primitive cases, independently checked and executed against both cores |
| Trusted clock/key/endpoint controls and compact wire expansion | `conformance.DecodeHTTPBoundaryInput`, tested against every expanded wire hash |
| Repeatable execution and rule-to-observation mapping | `scripts/inspect_http.py`, three complete suites, per-rule results and hashed report files |
| Missing support and spec interpretation limits | Explicit UNSUPPORTED results and six conditional size cases; no implicit certification |

[Detailed fixtures](http-boundary-vectors.md) define the bounded cryptographic
projection. The Go input helper validates harness controls, duplicate/unknown/null
JSON fields and bounded expansion; it does not verify the protocol. It preserves
malformed HTTP bytes and missing original requests so the subject makes the actual
accept/reject decision. An invalid harness control is an execution/configuration
error, never a passing negative protocol test. Rust integrations use the same JSON
contract; no Go-specific wire semantics are introduced.

The built-in reference intentionally does not implement these operations. The
Node checker audits the restricted fixture grammar and is not offered as a target
core verifier. Positive fixture audits therefore cannot be mistaken for measured
core acceptance.

## Run all inspections

Build `cmd/sage-conformance` and a subject adapter as described in
[core-adapters.md](core-adapters.md), then use a new output directory:

```sh
python3 scripts/inspect_http.py \
  --runner /absolute/path/to/sage-conformance \
  --adapter /absolute/path/to/core-adapter \
  --subject sage-go-core \
  --revision FULL_CORE_COMMIT \
  --output-dir /absolute/path/to/new-evidence-directory
```

The command runs `http-signatures`, `http-boundaries` and
`http-envelope-primitives` with the same subject and executable. It writes three
ordinary conformance reports and `summary.json`, retaining suite hashes, subject
revision/executable hash, report file hashes, per-rule case references, counts and
conditional cases. The 134 entries are fixture cases, not 134 distinct normative
requirements. The original 386-case traceability baseline is not reclassified.

Existing output directories are refused to protect prior evidence. Runner failure
or incomplete/corrupt reporting produces ERROR and exit2, without a successful
partial summary. FAIL exits1. Unsupported/unrun or unresolved conditional cases
produce INCOMPLETE and exit3 unless FAIL takes precedence. Even hypothetical PASS
results for all subjects cannot hide the six conditional field-counting cases.
These exit codes describe the subject evidence, not the implementation status of
this inspection workflow.

## Current observations

| Core | PASS | FAIL | UNSUPPORTED | NOT_RUN | Conclusion |
|---|---:|---:|---:|---:|---|
| Go c7709b7486e0da94336edc0931fddd87f6a45343 | 51 | 8 | 75 | 0 | FAIL |
| Rust 206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2 | 55 | 4 | 75 | 0 | FAIL |

[Go summary](evidence/http-inspection/go/summary.json),
[Rust summary](evidence/http-inspection/rust/summary.json).
The 75 unsupported entries are the six legacy reserved boundary cases plus the
69 complete-contract cases. These summaries use one unchanged adapter executable
per core for all three suites. Prior individually collected reports are preserved
as historical evidence. Existing core mismatches are described in
[HTTP signature evidence](http-signature-vectors.md).

## Follow-up after core implementation

1. Bind the core's raw HTTP/envelope validation entry point to `sage.http.verify`.
   Supply fixed trusted time, explicit receiving endpoint/recipient, test key
   observations and fresh isolated state through test controls. Do not change
   signature bytes, disable freshness or implement missing core checks in the adapter.
2. Apply the documented compact recipe before the subject receives the bytes.
   Use the Go helper or an equivalent Rust binding; both must reproduce the pinned
   expanded hashes. Keep ordinary malformed-wire handling inside the core boundary.
3. Rebuild and record the new core revision and executable hashes, rerun the complete
   bundle into a new evidence directory, and compare per-rule observations. Genuine
   failures remain FAIL; do not revise expectations just to match a core.
4. Clarify the field-octet counting convention in the spec, update the pinned baseline
   deliberately, and revise the six conditional cases only if the normative rule
   differs. The current convention and open interpretation are explicit in the
   fixture documentation and machine-readable summary.
5. Retire the six historical reserved cases through an explicit suite revision once
   their replacements are bound. They are not silently promoted or double-counted
   as additional requirement coverage.

Replay persistence/concurrency, HPKE/session interpretation, actual registry
resolution, dispatch effects and host bypass checks remain in their respective
planned work. They are not implicitly certified by this HTTP cryptographic projection.

## Validation

The Go contract tests cover all 69 expanded messages, including malformed-wire
negatives, and invalid harness controls. Independent fixture audits and aggregation
regressions run in CI. Aggregation tests reject missing suites, mixed identities,
wrong suite hashes/counts, duplicate/missing observations and false PASS promotion.
The same bundle command has been run against both current core adapters; local
race tests and vet also pass.
