# ADK admitted downstream capture source inspection

This sixth explicit source snapshot pins `sage-adk`
`e2653847e7d75507e1561e36baebcf321ca3307c`, preserving SAGE 0.10.0 normative
revision `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. It reviews the retained
original for downstream calls from an actually admitted native MCP worker.
This is library integration without a protocol, RFC carriage or wire change.

The [catalog](../verification/0.10.0/adk-admitted-hop/catalog.json) hashes 183
tracked non-test Go files and both unchanged module files. Compared with the
fifth snapshot, only `core/capture/policy.go` changes and `core/capture/hop.go`
is added. The [saved query](evidence/adk-admitted-hop.json) parses 1,248
declarations and 6,099 syntactic calls and matches 119 reviewed boundaries.
All 105 preceding route rows remain identical. Four previously unclassified
policy/signing wrappers are reviewed against the changed retained-input
interface; ten new hop rows cover three metadata-only and seven opt-in
admission/capture boundaries. The eight earlier testdata fixture rows remain
separate. New ADK `_test.go` files are excluded from the source inventory.

All five preceding catalogs and reports are preserved byte for byte:
[routes](adk-source-inventory.md),
[approved operation](adk-approved-operation-inspection.md),
[compiled calculator](adk-compiled-calculator-inspection.md),
[sealed executable](adk-sealed-image-inspection.md) and
[child measurement](adk-child-measurement-inspection.md).
Their conclusions describe their exact revisions. The historical route snapshot
remains the default; Registry reviews retain their separate pins and obligations.

## Reviewed boundaries

| Boundary | Manually reviewed behavior | Responsibility outside this query |
| --- | --- | --- |
| `ID`, `Digest`, `ParentCallID` | Local metadata and causal parent ID only. No raw root Request or native parent admission is exported. | Metadata is not authorization or inherited permission. |
| `hop`, `HopRequest.check` | Mandatory actual Invocation, upstream authority/policy and independently configured local recipient; bounded original; native parent checks before/after fresh upstream verification; exact canonical bytes and Invocation digest. Failure/panic retires the capability. | Providers must be isolated, bounded, concurrent-safe and non-reentrant. Pre-entry cancellation refuses. JSON extraction alone supplies no verification. |
| `Host.CaptureHop` | Live parent verified before storing exact inbound as a fresh local original; fresh ID differs from upstream; readback rechecks parent. | Retain durable history after failure; do not automatically retry with a fresh ID. Storage and checkpoint custody must be protected. |
| `Host.RestoreHop` | Existing protected ID/digest restored against the exact same currently admitted parent and original; refuses upstream ID. | Stored history cannot revive finished/UNKNOWN parent. Ordinary restart supplies no native parent admission. |
| `HopRequest.Inputs` | Current parent/upstream checks surround durable readback; exactly one retained original equals inbound; inconsistent storage/provider errors or panic permanently retire. | Readback and later effect are not an atomic transaction; native admission/fencing still applies. |
| `HopRequest.NewIntentIssuer` | Own issuer equals local recipient; mandatory own providers; capture-bound own policy/approval/signer; native hop issuer receives exact original and real parent. | Own downstream permission, signing custody and loaded-runtime measurement are independently approved, never inherited from upstream. Core supplies one-use approval and durable fencing. |
| `HopRequest.OpenMCPClient` | Rechecks original and live parent; wraps own policy; transfers exact signed bytes and actual Invocation through native `OpenHopClient(..., false, ...)`. | Already issued successfully closed journal, protected path/fence/bytes and authenticated connection ownership are required. Missing history is refused, never recreated. |
| Private retained-input wrappers | Exact local ID/digest; original checks around policy bindings, authorization and approval, and before protected signer delegation. Both root and hop capture use the private interface. | Wrappers do not attest provider integrity or establish atomic cross-provider authorization. No model-facing unsigned dispatcher is introduced. |

Complete source hashes cover private fields, interfaces, constants, conditions,
provider-presence checks and the `create=false` argument. Selected AST call
anchors do not prove their semantics, ordering, data flow or enforcement. Calls
repeated at the same line are not unique anchors. This is not an exhaustive
effect graph, type resolution, isolation proof or dynamic-plugin analysis.

## Reproduction and refusal tests

Use a clean, quiescent checkout at the exact reviewed revision:

```sh
go build -o /tmp/adk-source-inventory ./tools/adk-source-inventory
ADK_SYNTAX_PARSER=/tmp/adk-source-inventory python3 -B scripts/test_adk_source_inventory.py
python3 -B scripts/inspect_adk_source_inventory.py \
  --snapshot admitted-hop \
  --adk-root /path/to/pinned/sage-adk \
  --parser /tmp/adk-source-inventory \
  --check docs/evidence/adk-admitted-hop.json \
  --output /tmp/adk-admitted-hop.json
```

Scenario units refuse missing/duplicated declarations and every selected new
hop/wrapper call, altered source/module/catalog hashes, mixed revisions,
fixture promotion and fabricated conformance fields. They preserve the five
historical reports and exact unchanged routes/source sets. Synthetic AST units
check refusal only; they do not execute a parent admission.

Safe parser CLI tests refuse unreviewed revisions for all six snapshots without
creating a report. CI checks all six saved reports using separate pinned
checkouts and retains outputs. Only the trusted Inspector parser executes;
inspected ADK initializers, tools, plugins, child hosts and runtime fixtures do
not execute. Source/Git checks run before and after parsing. Trusted quiescent
storage remains required; concurrent hostile writers are not isolated. Check
exit status and do not reuse stale output after a failed query.

[ADK PR 14](https://github.com/SAGE-X-project/sage-adk/pull/14) separately tested
safe unit and native encrypted loopback scenarios for allowed downstream
execution, same-live-parent restoration, upstream policy loss, downstream policy
refusal and missing journal. Those tests use ephemeral keys, fixture Registry,
policy and measurement, fixed arithmetic and one Go core. Their evidence is
separate from this query and is not independent cross-core hop, deployed-host
conformance or an independent effect observer. No attack-capable reproduction
or host-bypass code is added here.

## Remaining work in the approved sequence

Retained hop capture, independent own issuer wrapping and native existing-journal
handoff are available as opt-in library capabilities. `guardbinding.Open` still
supports roots only. Continue concrete independently approved hop-operation and
loader assembly, then authoritative blockchain Source and selected protected
host/providers, then independent effect/deployment observations. Ordinary
`LoadedTool` callbacks receive arguments, not native Invocation or signer;
keep native admission and key custody in the trusted coordinator.

Preserve all nine gates in the [remaining-work register](remaining-work.md),
historical evidence and later contract upgrade, demo and A2A/DID stages.
The query is `AST_QUERY_EXECUTED`; query ADK runtime, all thirteen deployed
controls and independent hop execution remain `NOT_RUN`. Host selection remains
`SELECTION_PENDING`, effect observations are absent and full conformance remains
`NOT_ESTABLISHED`. Source matching does not close deployment obligations.
