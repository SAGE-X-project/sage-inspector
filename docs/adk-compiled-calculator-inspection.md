# ADK compiled calculator source inspection

This third explicitly selected source query pins `sage-adk`
`1da9d02226bd690f92ccc4198638afc84579a9e8` and the existing SAGE 0.10.0
normative revision `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. It inspects
`core/guardcalculator` and its use of ADK's existing compiled arithmetic tool;
it changes no protocol or wire requirement.

The [catalog](../verification/0.10.0/adk-compiled-calculator/catalog.json)
hashes 170 tracked non-test Go files and both module files. All 169 preceding
production files and module hashes are unchanged. The new production file is
`core/guardcalculator/calculator.go`. The [saved query](evidence/adk-compiled-calculator.json)
retains the preceding 49 rows and adds ten reviewed boundaries: nine
`COMPILED_CALCULATOR_OPT_IN` rows and one `LEGACY_UNMEDIATED` builtin row.
Direct use of the builtin is still unmediated; its presence does not make the
ordinary Agent, Tool Registry, A2A or gRPC routes protected.

The [historical route query](adk-source-inventory.md) remains the CLI default
at `afa469cdd8539992185235008ac1591c74012f7f`. The
[approved-operation query](adk-approved-operation-inspection.md) remains pinned
to `fb98773df57b258c29ff9c355d062158bdf56c0e`. Both catalogs and saved reports
are preserved byte for byte. They remain historical evidence, not queries of the
new source revision. The Registry preflight and mapping reports also retain
their existing pins and outstanding obligations.

## Reviewed boundaries

| Boundary | Reviewed implementation | Requirement outside the source query |
| --- | --- | --- |
| `NewFactory` and `enter` | Mandatory non-nil measurement, bounded instance ownership and cancellation-aware gates. | Protected host administration chooses and owns the provider; provider work must be bounded and honor cancellation. |
| `Factory.Load` and `componentArtifacts` | Exact policy/manifest commitments, owned artifact verification, configuration coverage and named image coverage in both component and evaluator descriptors. Measurement precedes constructing a private `tools.CalculatorTool` instance. | The static host image and dependencies are already loaded by the launcher. A trusted provider must prove protected verification before loading and retained immutable loaded identity. Calling a provider or hashing a mutable path after loading does not establish this. |
| `parseConfiguration` | Closed five-field version/tool/image/operations/operand-limit configuration; sorted unique allowed arithmetic operations and finite positive bounds. | Configuration and original-request policy are independently approved. The named image is descriptor data; the adapter does not open it or execute snapshot bytes. |
| `instance.checked` and `Check` | Exact commitments/tool identity, mandatory repeated measurement, retirement checks after the callback and refusal/retirement on failed observation or panic. | Source matching does not establish provider accuracy, isolation or OS enforcement. Factory/Instance capabilities must stay with trusted native host configuration. |
| `instance.Execute` | Canonical closed `operation`, `a`, `b` arguments, configured operation/finite operand limits, repeated measurement immediately before the same private `i.tool.Execute`, and canonical result bytes. | `guardbinding` and native admission supply current approval/authority; this Instance method is not a model-facing unsigned dispatcher. Core owns one-use approval, durable journals and result protection. |
| `Factory.Close` | Immediate retirement, serialized waiting for accepted bounded callbacks and clearing private tool/snapshot references; cancelled cleanup retains ownership for retry. | Providers cannot be forcibly interrupted by this gate. Shutdown order, independent effect observation and distributed retirement remain host responsibilities. |
| Existing `CalculatorTool` | Fixed compiled add/subtract/multiply/divide implementation with domain-error result data. | The constructor alone has no Guard authorization. Completed native execution can contain a division-by-zero domain error; it does not mean domain success. |

These are manual source reviews, tied to complete production-file hashes and
selected declaration/call anchors. AST matching does not prove call ordering,
condition enforcement, type identity, runtime reachability, data flow or an
exhaustive effect graph. No external dependency or reflective/dynamic dispatch
is resolved. All build-tag variants are parsed; platform execution is not
observed. Changes to unanchored expressions/constants still change source hashes
and require a new reviewed snapshot.

## Reproduction and refusal tests

Build only the trusted Inspector parser. Keep the inspected ADK checkout clean,
quiescent and at the exact calculator revision:

```sh
go build -o /tmp/adk-source-inventory ./tools/adk-source-inventory
ADK_SYNTAX_PARSER=/tmp/adk-source-inventory python3 -B scripts/test_adk_source_inventory.py
python3 -B scripts/inspect_adk_source_inventory.py \
  --snapshot compiled-calculator \
  --adk-root /path/to/pinned/sage-adk \
  --parser /tmp/adk-source-inventory \
  --check docs/evidence/adk-compiled-calculator.json \
  --output /tmp/adk-compiled-calculator.json
```

Units verify history preservation, exact source/module sets, snapshot mixing,
changed catalog revision/hash/classification/review and missing or duplicated
measurement/execution/retirement declarations and calls. Safe parser-CLI runtime
tests refuse unreviewed source revisions for all three snapshots and parse inert
Go files without executing their initializers or callbacks. The real pinned
calculator checkout is parsed and compared with its saved report. CI reproduces
all three reports from separately pinned checkouts with the Inspector-built
parser and preserves them as artifacts. No ADK, LLM or tool code is run by this
query; it introduces no attack-capable reproduction or host-bypass program.

Source checks run before and after parsing. Trusted quiescent storage is required;
these checks do not isolate a concurrently hostile local filesystem. Failed fresh
queries produce no new report. Check the process status and never reuse an old
output file as evidence of a failed invocation.

## Remaining work in the approved sequence

The query is `AST_QUERY_EXECUTED`. ADK runtime, thirteen deployed host controls
and independent hop execution remain `NOT_RUN`; host selection remains
`SELECTION_PENDING`, effect observations remain absent and full conformance
remains `NOT_ESTABLISHED`. ADK's own unit and native/external-consumer runtime
tests use fixture Registry and measurement providers. They remain separate
integration evidence, not deployed attestation or an authoritative blockchain
Source binding.

Concrete same-instance compiled arithmetic binding is available. Actual protected
runtime measurement, authoritative blockchain Source mapping/selection, a pinned
host executable/configuration and independent effect observation remain required.
Complete parent-hop policy/binding separately. Preserve the
[remaining-work register](remaining-work.md), all nine gates and the later
contract upgrade stage. This source query does not begin demo work, normative
A2A/DID upgrades or Registry write/deployment changes.
