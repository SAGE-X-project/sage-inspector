# Latest 0.10.0 specification inventory

Inspector pins the `sage-spec` case graph at revision
`44df132fee5925182018ce089dc82435cb353f8a`: 45 requirements, 91 rule
groups, 489 parent cases, and 26 mandatory subscenarios. The three files in
`verification/0.10.0/latest-spec/` preserve the source manifest, traceability
graph, and classifications for the 103 cases added since the 386-case baseline.
The catalog checks every case and requirement mapping, the exact source file
hashes, and the eight-case change from the [earlier 481-case inventory](current-spec-coverage.md).

The eight new cases are `msca-http-ed25519`, `msca-http-p256`,
`msca-http-private-alg`, `msca-http-only-private-key`,
`msca-http-no-substitution`, `msca-did-prefix-case`,
`msca-did-url-prefix-case`, and `msca-private-suite-non-http-scope`.
Their required verification track is runtime, combining unit tests and bounded
local execution. The [wire and HTTP binding vectors](wire-http-binding-vectors.md)
cover related source bytes and primitive checks, but do not establish these
complete normative cases.

Run the inventory against the exact `sage-spec` revision:

```sh
python3 -B scripts/test_latest_spec_catalog.py
python3 -B scripts/latest_spec_catalog.py \
  --spec-root /path/to/sage-spec \
  --report /tmp/latest-spec-inventory.json
```

The report marks all 489 parent cases and 26 mandatory subscenarios `NOT_RUN`
for this revision, with `NOT_ESTABLISHED` conformance. It is a case-plan and
source-integrity check, not an implementation result. Earlier fixtures and
observations remain bound to revision
`5bcf511e604579afa63f434013447f44b6858828`; no previous verdict is
silently inherited. CI checks both inventories against their respective source
revisions and publishes the latest report.

The eight new cases now have [source-exact partial host contracts](../verification/0.10.0/latest-spec/bindings.json).
Each fixture pins its case, rule, source location, trigger, preconditions and
normative expectation to the new revision. The local contract's `ACCEPT`
expectation means only that a future host observation matches that contract;
it does not mean the HTTP message or DID is accepted. No core observation is
included, so all eight remain `NOT_RUN`. Even a matching observation of these
partial contracts can reach only `PARTIAL`, never case `PASS`. Run the bounded
contract and evidence checks with:

```sh
python3 -B scripts/test_latest_spec_case_bindings.py
python3 -B scripts/test_latest_spec_evidence.py
python3 -B scripts/latest_spec_case_bindings.py --spec-root /path/to/sage-spec
python3 -B scripts/latest_spec_evidence.py --output /tmp/latest-spec-evidence.json
```

These contracts contain no signed request/response exchange, key selection,
replay transaction or protected dispatch. Version-matched implementation
adapters and independently recorded observations are required before the
new cases can acquire implementation results. The earlier 481 cases likewise
remain `NOT_RUN` for this newer revision until their bindings and evidence
are migrated deliberately.
