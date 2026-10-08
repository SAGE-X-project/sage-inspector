# ADK approved downstream operation source inspection

This seventh explicit snapshot pins ADK
`57f37e1c870d7bf1c5c6fdbd60efa1e62a6fcb6e` and its exact Go dependency
`f1a840bbc9c717564bd035e19c73f437a61e4a00`
(`v1.5.3-0.20261008045438-f1a840bbc9c7`). The unchanged SAGE 0.10.0 normative
source is `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. This is library
integration and source review; it introduces no protocol or RFC wire change.

The [catalog](../verification/0.10.0/adk-approved-hop/catalog.json) hashes 183
tracked non-test ADK Go files, 244 tracked non-test Go core files and both
repositories' module files. The [saved query](evidence/adk-approved-hop.json)
parses 1,251 ADK declarations / 6,113 calls and 2,025 core declarations /
13,589 calls. It matches 122 ADK boundaries and seven core clock/liveness
boundaries. The core is parsed independently; dependencies and initializers
are never imported or executed. All build-tag variants and examples are parsed.

All six earlier catalogs and reports remain byte for byte unchanged, including
their historical conclusions and default route snapshot. Relative to the
[sixth snapshot](adk-admitted-hop-inspection.md), five ADK production source
hashes and both module hashes change. Fifteen prior rows are re-anchored and
reviewed at the new source; 104 other rows remain identical. Three new rows
cover `OpenHop`, private shared loading and exact root/hop parent matching.
The eight earlier testdata rows remain `RUNTIME_TEST_FIXTURE`. New ADK test
files are outside the production syntax inventory.

## Reviewed behavior

| Boundary | Manually reviewed behavior | Remaining trust obligation |
| --- | --- | --- |
| `Open` / `OpenHop` | Separate typed root/hop constructors. Hop input freshly checks actual parent/current upstream, exact retained inbound and parent UUID. Independently approved local issuer must equal authenticated inbound recipient before files or loader access. | Stored metadata cannot reconstruct native admission. Own downstream permission and signing custody are independent. |
| Private `open` / retained input | Exact policy/component descriptors and approved bounded artifact snapshot precede loading. Retained input is checked immediately before one immutable `Factory.Load` and again through final instance checks. | Factory receives only Snapshot. Actual loaded evaluator/tool/dependency identity, isolation, protected baselines and bounded provider behavior remain required. |
| `ApproveIntent` / `parentMatches` | Closed seventeen-field intent retains exact own identity, key, original, commitments, profile, arguments and lifetime checks. Roots require null; hops require exact retained parent and a different child call ID. | Parent ID is causal metadata. Core still supplies current Registry/time validation, one-use approval and durable issuance fencing. |
| Binding, measurement, effect and retirement | Same private loaded instance and current retained original are checked under the shared operation gate. Closing refuses new work and retains cleanup ownership on timeout. | Binding is a trusted coordinator capability, not unsigned model dispatch. Own issuing operation cannot attest a remote receiver. No atomic transaction across independent providers or rollback proof is supplied. |
| Core `sample` / `sampleLocal010` | Protocol and native timer share one ordered local-clock history. `clockMu` covers only the bounded local clock and last-stamp comparison/publication. Retirement, finite nonnegative stamps and actual monotonic/UTC rollback still refuse. | Clock must be protected, bounded and non-reentrant. No Registry/storage/cryptography/key cleanup runs under this clock lock; local sampling is not external attestation. |
| Core `LocalNow` | Atomic validated/activity/confirmation bounds are read before sampling. Later legitimate publication does not retroactively invalidate that earlier sample. Session, pending/idle/lifetime, key-expiry and duration bounds remain enforced. | Timer does not replace fresh Registry validation, expose signing secrets or authorize an effect. |
| Core `recordLive`, `recordGate`, `checkCurrent010`, `Observe` | A legitimate protocol start is not compared with a later timer-only sample. Final samples still enforce current Registry/key state, expiry, liveness and five-second validation budget before publication. | Matching syntax cannot prove concurrency semantics or production timing. Observe returns diagnostic start timing, never portable authority. |

Whole-file hashes cover private interfaces, fields, constants, conditions and
arguments. Selected AST calls establish presence at the pinned source, not
data flow, ordering, reachability, concurrency correctness or complete effect
mediation. Repeated identical calls at one line are not unique anchors. This
is not a complete effect graph, type-resolution pass or hostile-filesystem
isolation boundary.

## Reproduce and test

Supply clean, quiescent checkouts at both exact revisions:

```sh
go build -o /tmp/adk-source-inventory ./tools/adk-source-inventory
go test -race ./tools/adk-source-inventory
ADK_SYNTAX_PARSER=/tmp/adk-source-inventory python3 -B scripts/test_adk_source_inventory.py
python3 -B scripts/inspect_adk_source_inventory.py \
  --snapshot approved-hop \
  --adk-root /path/to/pinned/sage-adk \
  --go-root /path/to/pinned/sage \
  --parser /tmp/adk-source-inventory \
  --check docs/evidence/adk-approved-hop.json \
  --output /tmp/adk-approved-hop.json
```

The query requires both roots and the exact ADK module dependency; historical
snapshots refuse an extra core input. Source checks refuse wrong revisions,
dirty/untracked or ignored Go files, symlinks, changed hashes, missing/new
sources, parser errors and catalog/report drift. Both roots are checked before
and after their query. Units test missing/duplicate approved-operation and
clock anchors, changed source sets, module/dependency drift, missing core,
mixed historical evidence and fabricated conformance. Synthetic AST units
test refusal only and supply no actual admission. Safe CLI tests parse inert
sources without executing them and refuse invalid input without creating a
report. After a failure, do not reuse stale output.

CI runs the parser's race/unit and CLI tests, checks all seven saved reports
against separate exact public source checkouts and retains outputs. No ADK
host, Go core, plugin, tool or vulnerability reproduction executes in this
source query.

[ADK PR 15](https://github.com/SAGE-X-project/sage-adk/pull/15) separately
checks safe real encrypted A-to-B-to-A loopback with durable journals,
ephemeral registered Ed25519/X25519 keys and the actual compiled calculator.
Allowed completion signs once, attempts the protected receiver callback once
and verifies result 5. Independent policy refusal, missing measurement,
retired operation and upstream policy loss check zero child signing and zero
attempted protected receiver callbacks. A finished parent refuses another
loader; foreign local issuer is refused while the real parent is live.
Issuance and receiver bindings are co-located, and Registry/loaded-runtime
assurance are synthetic. These tests are separate local integration evidence.

[Go PR 426](https://github.com/SAGE-X-project/sage/pull/426) separately
checks ordinary timer/validation progress and continued refusal of actual
monotonic/UTC rollback. Its final merge and the ADK final merge passed their
applicable CI checks. These results do not certify deployment or independent
cross-core hop execution; this query reports core and ADK runtime `NOT_RUN`.

## Continue in the approved order

Approved local hop policy/artifact/loader assembly is now available alongside
retained native hop capture and existing-journal handoff. Next identify and pin
the authoritative blockchain Source and selected protected host/providers,
then gather independent effect/deployment observations. This requires real
chain ID, RPC, contract address and ABI/deployment version, protected actual
policy/key/measurement providers and supported final effects. Do not silently
select a test Registry or synthetic assurance as production authority.

All nine gates in the [remaining-work register](remaining-work.md) stay visible.
Host selection remains `SELECTION_PENDING`; all thirteen deployed controls
and independent hop execution remain `NOT_RUN`; effect observations are absent
and full conformance remains `NOT_ESTABLISHED`. Historical records, contract
upgrade, demo and later normative A2A/DID stages keep their existing order.
