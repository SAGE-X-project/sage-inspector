# HPKE inspection

INS-06's spec-based Inspector implementation is complete: 30 primitive cases,
37 complete-schedule/completion cases and six lifecycle scenarios (20 ordered steps).
Core implementation support and security assurance are separate states.

## Independent expected values

[Generator](../scripts/generate_hpke_vectors.py) imports no SAGE code. It uses Python
hashlib/HMAC, HKDFExpand and X25519 to produce B, info, exportCtx, enc, exporterHPKE,
ssE2E, T, th, prk, seed, ackKey, ackTag, sid and signed completion bytes. It also
records the RFC KEM shared secret, key-schedule context, secret and exporter secret.

Published RFC9180 Appendix A.2.1 values anchor the exact Base suite0020/0001/0003
with three export contexts. RFC5869 Appendix A.1 anchors expansion. The verified
RFC9180 erratum7937 KEM suite prefix is used; private byte inputs are serialized
X25519 keys, with the primitive applying scalar clamping. The profile uses AEAD0003,
not the RFC's different export-only AEAD identifier. All deterministic keys and
nonces are public test material, not production credentials or evidence of entropy.

[Node checker](../scripts/check_hpke_vectors.js) independently rebuilds the schedule
using ECMAScript serialization, Node X25519, HMAC expansion and signatures. It checks
every recorded intermediate and verifies positive/negative verdicts and fixture
rejection reasons. The static lifecycle model checks expected transitions/counters;
it is not a core adapter or proof of real effects. The two language paths may share
OpenSSL and are not an external expert audit.

## Operation contracts

| Operation | Input | Successful output / actual binding |
|---|---|---|
| `rfc9180.export` | Hex private key, enc, info and export_context | `exporter_hex`; actual Go HPKEOpenSharedSecretWithX25519Priv and Rust kem_open |
| `x25519.exchange` | Hex local private and peer public bytes | `shared_secret_hex`; Rust X25519KeyPair.diffie_hellman; Go raw-equivalent binding unavailable |
| `sage.hpke.combine` | exporter_hex, ss_e2e_hex, th_hex | `seed_hex`; actual legacy combiner helper with normative th supplied as salt, preserving observed differences |
| `sage.hpke.derive` | B binding, four deterministic private-key controls, UUID kid | Exact named intermediates in fixture output; future 0.10.0 complete derivation binding |
| `sage.hpke.complete.verify` | Stored pending initiation/private controls/current signing public observation and received completion_hex | seed_hex, th_hex, sid after all projection checks; future core binding |
| Existing JCS/signature operations | Fixed B/T and completion signing bytes | Actual core canonicalization and signature verification |

REJECT has empty output. Invalid IPC hex or local deterministic private-key controls
are execution errors; invalid peer enc/public values go unchanged to the selected
subject API. The Go adapter does not substitute its hashed DeriveSharedSecret helper
for raw X25519. Missing complete 0.10.0 APIs remain UNSUPPORTED. The selected legacy
combiner cannot pass the new label/salt schedule by normalizing its output.

The completion projection assumes the containing initiation/response envelopes and
current key observation were authenticated at their own boundaries. It tests inner
schema, selected pending identity, signature, DH and ACK; it does not reimplement the
HTTP/envelope verifier. Its pending input includes the original initiation plus
initiator HPKE/C private controls, selected responder KEM public bytes and signing
public bytes. The different-pending case supplies an internally consistent second
pending state. Received completion bytes, not regenerated messages, are passed to
the subject.

## Coverage and state contract

The primitive/schedule cases cover RFC anchors, independent role/context variants,
changed info/export context, null and short DH inputs, invalid combiner components,
every echoed initiation field, correctly signed wrong ACK, missing/padded/invalid
signatures and ACK, closed schemas, version/suite/combiner rejection, zero/short S,
invalid handle and completion payload size16384/16385. A changed RFC export context
correctly produces another exporter rather than claiming Base HPKE authenticates it.
Completion authentication must detect inconsistent contexts.

Stateful fixtures use schema2 and one process per scenario:

- `control.hpke.pending`: install the supplied already-emitted pending fixture with
  emitted_utc, emitted_monotonic and initiation_expires integer seconds. Return
  INIT_SENT with zero cumulative sessions_created/pending_destroyed counters.
- `subject.call`, action `hpke.complete`: deliver completion_hex at explicit trusted
  UTC/monotonic values with bound_keys_current and outer_response_authenticated test
  observations. These are trusted harness controls, never peer-controlled wire flags.
  Success returns ESTABLISHED and sid. Failure returns REJECT with empty output.
- `subject.call`, action `hpke.inspect`: return state and pending_present, plus exact
  cumulative logical session-creation/pending-destruction counters.

Scenarios cover valid completion, wrong ACK, another pending initiation, equality at
UTC expiry and the300s monotonic bound, and invalid bound keys. Wrong-ACK and
wrong-pending cases retry after destruction and require rejection without creating
state or incrementing destruction again. Counters require real instrumentation;
missing instrumentation must be UNSUPPORTED, never fabricated zero effects. Logical
pending destruction is not by itself evidence of physical zeroization.

Responder first-record confirmation, AEAD and replay atomicity depend on session
records and remain in INS-07. This separation is not a claim that HPKE-05 as a whole
has passed. The [security review](hpke-security-review.md) separately addresses
secrecy/authentication assumptions and compromise timing.

## Run and evidence

```sh
python3 scripts/inspect_hpke.py \
  --runner /absolute/path/sage-conformance \
  --adapter /absolute/path/core-adapter \
  --subject core-name --revision FULL_CORE_COMMIT \
  --output-dir /absolute/path/new-evidence-directory
```

Add `--scenario-runner /absolute/path/sage-scenario` and
`--state-adapter /absolute/path/state-adapter` together after a real state binding
exists. A schema1 primitive adapter is not a state adapter. Without that binding,
the six scenarios are NOT_RUN and their fixture hashes remain in the summary.
This does not block Inspector implementation readiness.

Each run preserves fresh report files, suite/fixture/report hashes, rule-to-case
observations, subject revision and executable hashes. Existing output directories
are refused. Failure/unsupported/unrun results are not counted as passing; errors
produce exit2, observed FAIL exit1, INCOMPLETE exit3, and scoped PASS exit0.
No status is full-protocol certification.

| Subject | PASS | FAIL | UNSUPPORTED | Stateful scenarios |
|---|---:|---:|---:|---|
| Go c7709b7486e0da94336edc0931fddd87f6a45343 |20|5|42|6 NOT_RUN|
| Rust206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2 |23|7|37|6 NOT_RUN|

[Go evidence](evidence/hpke/go/summary.json),
[Rust evidence](evidence/hpke/rust/summary.json).
Both cores reproduce the RFC/SAGE exporter expectations at the selected recipient
API and reject the KEM negatives. Both legacy combiners differ from the 0.10.0 seed
and accept zero/short direct components at that helper API. Rust's raw DH helper
accepts the tested null results; its higher-level handshake separately rejects zero,
so this is not reported as a demonstrated complete-handshake exploit.
Complete derivation/completion remains unsupported in both; Go also has five
unsupported raw-DH cases. No core source was changed. [Provenance](evidence/hpke/provenance.json)
records consulted source hashes, RFC anchors and tooling versions.

## Checks and follow-up

```sh
python3 scripts/generate_hpke_vectors.py /tmp/new-hpke-fixtures
node scripts/check_hpke_vectors.js
python3 scripts/test_hpke_inspection.py
make test-foundation
```

Generation is byte-reproducible. CI runs independent calculations, corruption tests,
strict loader/reference checks and state-control unsupported propagation. Actual
adapter builds/executions are recorded locally rather than implied by root CI.
After core implementation, bind the exact operations/test controls, pin its new
revision, rerun all suites/scenarios and compare outcomes. Expectations remain
spec-derived; changing them requires a deliberate specification/baseline review.
The original386-case traceability baseline is not automatically marked executed.
