# Inspecting one-observation DID pairs

This separate subject inspects the public `advanced/sage.ObserveViews` operation
against adopted SAGE 0.10.0 revision
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`, chapter 10 DIDP-03. It is not the
historical DID observer assembling two separate Source/Produce calls. The
published module is fixed in `verification/0.10.0/a2a-did/did-paired-subject.json`;
there is no workspace or replacement of either public dependency.

The original `did-profile` fixture, adapters, subject pins and historical
23 PARTIAL / 2 FAIL / 3 UNSUPPORTED result remain unchanged. The repaired
`did-response-current` subject's 25 PARTIAL / 3 UNSUPPORTED result is also
unchanged. This new subject gives only the bounded paired-operation case a
PARTIAL verdict after all eight scenarios agree; every other adopted case is
NOT_RUN. Results from these subjects, DID standards and document actors are not
added or subtracted from each other. No new full-conformance PASS is inferred.

Each fresh native process calls the actual public API. The changing Source
returns active versions 7 and 8 across two invocations with one update-services
mutation: controller, keys, raw material, state and expiry remain unchanged while
the service URI changes. Each pair must agree with complete independently
authored document and metadata expectations; equal version strings alone are
insufficient. The next invocation must acquire a new observation. No fixture
expected values are passed to the process.

Created, deactivated and unusable-key snapshots preserve service/state and omit
verification relationships. Source failure and a second-production failure must
return no pair. A different-method DID must be rejected without a Source or
producer call. An ordinary scratch-buffer producer and caller mutation exercise
independent returned byte/metadata ownership. The observer preserves a returned
pair even alongside an error, so partial-return defects cannot be hidden by the
wrapper. Malformed actual output and any full-body mismatch yield FAIL; incomplete
reported scenario sets cannot close the contract. Unrecognized input identities
are rejected as invalid observation admission.

The Source is an explicit fixture, not a Registry proof provider or a selected
operating authority. The public API delegates source authority/freshness/history
validation to its configured Source. These tests do not establish protected
message authority, a peer-document/alias verifier, an HTTP resolver, deployed
registry history or source/custody qualification. The Go dependency's production
API bytes are unchanged by the subsequent history-preserving test refinement.
The companion Rust paired API has its own independently scoped evidence.

The inspection workflow first checks the adopted spec snapshot and exact public
module selection. It then builds and launches eight real native processes before
self-tests. It retains actual raw stdout/input identities, public dependency
checksums, compiled BuildInfo, compiler, source and binary digests before/after,
and exact head/tree. Scenario-based Go units/race, Python observer units and
statement coverage run with their existing 90% thresholds. Reported binary hashes
and source bindings are not compiled-byte attestation. Python mock/report tests
are observer self-tests and are never published as actual core execution.

The report output is created exclusively. An existing file or symlink target is
preserved, and a report with a finding remains available before the CLI exits
with failure. CI artifact run/revision identity and the committed input/observer
files provide the reproduction path; temporary receipt files are not permanent
storage or authorization evidence.
