# Adopted DID projection and resolution observations

This observer connects all 28 DIDP cases from the adopted specification
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`. Historical evidence remains bound to
its original revision. No inventory row is promoted to complete conformance.

The subject is the actual `github.com/sage-x-project/did-go/advanced/sage` module
at `2ef282b40ccfe243c6cf3b1c05594e02171126cc`, using the root module at
`ed54c505eafe1c9d3d2decd862d6a9f7fcd2cd23`. This does not certify the current
Go or Rust core, the separate did-inspector project, or a deployed resolver.

## Independent expectations and execution

`vectors/0.10.0/did-profile-observations.json` supplies 25 executable contracts
and three explicit unsupported contracts. The construction script is preserved
in `verification/0.10.0/a2a-did/did-fixture-construction.py.txt`. It builds public
JWK coordinates and document members from the adopted specification, without
calling the subject or copying its output. The public Ed25519 test key, X25519
basepoint and P-256 generator require no private keys or transactions.

Each executable case runs in a separate bounded process. The observer verifies
Go 1.26.8, public module versions and sums, the module cache, compiler inputs,
source hashes and the executable before and after execution. Raw stdout and
response bytes remain in the execution report. Duplicate JSON members, unknown
observation fields, boolean counters and incorrect body value types are rejected.

SAGE interface cases call `sage.Respond` directly. Their reported error status
comes from its problem object, not from a production HTTP exchange. DID
Resolution interface cases use the actual `sage.Handler`, `sage.Resolver` and
standard DID resolver through an owned loopback TLS server with its trusted test
CA. The process denies and counts default HTTP transport requests; zero such
requests is not an OS-wide no-network guarantee or proof about a deployed host.

The fixture Source explicitly supplies prevalidated record data or a diagnostic.
It does not establish registry proofs, authorization, freshness or key custody.
For the unknown-kind case it supplies `id.unknown-kind`; the case observes error
mapping, not a production registry-kind parser. A producer failure prevents the
DID 1.1 result; the observer checks that no DID Core 1.0 document replaces it.

## Findings retained as FAIL

The pinned subject produces 23 PARTIAL results, two FAIL results and three
UNSUPPORTED results; the other 555 adopted cases remain NOT_RUN.

| Case | Required result | Observed result |
|---|---|---|
| `didp-02-json-envelope` | `didDocumentMetadata.deactivated` is the boolean `false` for the active record | The member is omitted |
| `didp-05-unsupported-accept` | HTTP 501, `FEATURE_NOT_SUPPORTED`, and `sageCode: representation.unsupported` | Status and problem type match, but `sageCode` is omitted |

Both normative expectations remain unchanged. Ordinary CLI execution returns a
nonzero status when it records these findings. The explicit `--record-known-gap`
option lets CI preserve these exact two findings for later implementation work;
it never changes their FAIL verdicts. Any different finding, additional failure,
or change in the known discrepancy fails that mode. CI tests assert this
revision-bound behavior. Once the implementation changes, the subject pin and
these assertions require review rather than silently accepting the new output.

These fixes remain implementation work in the approved core migration stage.
This inspection change does not alter the adopted specification or those cores.

## Scope limits

The two projections are compared against independently specified complete JSON
members. Raw bytes are retained; arbitrary representation formatting is not a
new normative canonicalization rule. Calls selecting both projections use two
separate `Respond` calls against the same fixed fixture record. They do not
establish a dual-request operation reading one authoritative observation, or
metadata/version consistency during a concurrent registry change.

Three cases remain explicitly UNSUPPORTED in this observer:

- `didp-03-two-observations`: the pinned subject has no changing-Source dual
  projection operation that this adapter can exercise.
- `didp-04-peer-document-ignored`: this projection/resolution subject does not
  expose a protected-message verifier accepting a peer document.
- `didp-04-received-alias`: it likewise cannot test authorization from a received
  alias. Omitting aliases from produced documents is not verifier evidence.

No result certifies the full SAGE HTTP binding, production TLS identity,
protected-message key selection, signatures, replay defense, authoritative
registry observation or deployed assurance. These observations have a different
subject from the A2A ADK reports and are not combined into one subject verdict.

## Commands and next work

From the Inspector root, download the pinned modules in `adapters/did-profile`,
then run:

```sh
python3 -B scripts/test_did_profile_observation.py
python3 -B scripts/test_did_profile_process.py
python3 -B scripts/did_profile_observation.py --native --output /tmp/did-profile.json
```

The last command writes the report and exits nonzero for the two known findings.
Use `--record-known-gap` only to preserve the documented pinned findings in CI.
Next in the approved inspection sequence are the two TABLE-08 cases and separate
did-inspector coverage of the advanced/sage subject and the DID 1.0/1.1 judgment.
