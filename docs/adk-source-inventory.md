# ADK source route inventory

This source review pins `sage-adk`
`afa469cdd8539992185235008ac1591c74012f7f` and the unchanged normative
SAGE 0.10.0 source `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`.
The [catalog](../verification/0.10.0/adk-source-inventory/catalog.json) records
hashes for every tracked non-test Go source and both module files. The
[query report](evidence/adk-source-inventory.json) records 29 reviewed route
anchors across 163 source files. The Inspector CLI parses source with Go's
standard AST parser; it does not import or run ADK, load dependencies, contact
an LLM, invoke tools or connect to a Registry.

## What is protected and what still needs integration

| Reviewed route | Source classification | Consequence for host assembly |
| --- | --- | --- |
| `core/toolhost` native owner and `executor.Run` | `GUARD_NATIVE_OPT_IN` | Live admission, current intent validation and same-instance measurement precede execution on this path. The host must still bind isolated policy, current Registry authority, custody and an approved loader. |
| `agent.ProcessOriginal` | `CAPTURE_ONLY` | Retains original input before decoding and callback invocation. It does not mediate effects performed by the callback. |
| Captured issuance/Client transfer and Guard signers/clock | `PROTECTED_PROVIDER` | Assembly ports with explicit host obligations. Signing is not approval or fencing; the local clock is not external attestation. |
| Tool Registry, FunctionTool, ordinary Agent handler and middleware | `LEGACY_UNMEDIATED` | Ordinary callbacks can execute effects without the native owner. Registry getters expose raw tool capabilities. Protected host configuration must not expose them to untrusted routes. |
| A2A, unary/streaming gRPC and CLI handler | `LEGACY_UNMEDIATED` | These existing entry points invoke ordinary callbacks. Installing the native tool host does not automatically protect them. |
| Legacy SAGE message signing | `LEGACY_UNMEDIATED` | Separate historical transport format, including optional signing. The helper named RFC9421 explicitly does not establish HTTP signature conformance. |
| Builder callbacks, start hook and protocol construction | `CONFIGURATION_ONLY` | Optional lifecycle hooks do not establish a mandatory per-request or pre-decision checkpoint. SAGE/automatic server construction remains unimplemented. |
| Parsed function arguments | `PROPOSAL_ONLY` | Model arguments remain a proposal, not approved execution. |
| OpenAI, Anthropic and Gemini tool completions | `OUTBOUND_LLM_PROPOSAL` | External LLM requests return proposals; neither tool execution authorization nor protected prompt transport follows from this API. |

These classifications come from manual source review. Matching an AST anchor
only confirms that the reviewed declaration and named syntactic calls remain
at the pinned source. It does not prove authorization, isolation, runtime
reachability, execution ordering or the absence of other effects. All other
declarations remain unclassified. This is not a complete effect graph.

All tracked non-test Go files are parsed, including examples, generated code
and mutually exclusive build-tag files. Calls inside nested function literals
are attributed to the enclosing declaration; package initializer calls are
recorded separately. The parser exports no argument values or literal bodies.
Type resolution, external dependencies, reflection and dynamically loaded
plugins remain outside the query. A selected host needs an inventory of its
actual loaded executable, configuration, components and final effect owners.

## Reproduce and test

Use a clean, quiescent ADK checkout at the exact revision above and a trusted
parser built from this Inspector checkout:

```sh
go build -o /tmp/adk-source-inventory ./tools/adk-source-inventory
ADK_SYNTAX_PARSER=/tmp/adk-source-inventory python3 -B scripts/test_adk_source_inventory.py
python3 -B scripts/inspect_adk_source_inventory.py \
  --adk-root /path/to/pinned/sage-adk \
  --parser /tmp/adk-source-inventory \
  --check docs/evidence/adk-source-inventory.json \
  --output /tmp/adk-source-inventory.json
```

The query refuses revision/hash drift, dirty or untracked files, ignored
untracked Go files, missing/new production sources, missing reviewed anchors,
symlink sources, oversized files and parse errors. It checks source before and
after parsing and produces no successful report from a failed query. These
checks assume a quiescent trusted checkout; they are not filesystem isolation
against concurrent hostile mutation. Python units cover report/catalog drift
and Git provenance; Go units and safe parser-CLI runtime tests cover syntax and
refusal behavior without executing inspected sources. CI reproduces the saved
report from the pinned public ADK revision.

## What this does not close

`AST_QUERY_EXECUTED` is a source-query result. ADK runtime remains `NOT_RUN` in
this report and effect observations are absent, not a fabricated zero. Earlier
ADK loopback runtime tests retain their own narrower packaging evidence.
No host is selected, all 13 deployed host-port controls remain `NOT_RUN`,
independent hop execution remains `NOT_RUN`, and full conformance remains
`NOT_ESTABLISHED`. Historical manifests retain their original revisions.

Within the existing core/consumer work, continue with concrete protected host
assembly: independently selected policy and approved loaded component, final
supported effect mediation and verified result release. Bind the authoritative
blockchain Registry only after chain ID, RPC, contract address and ABI/deployment
version are identified. Then select and pin the executable/configuration,
providers, supported effects and independent observer, and run the existing
Inspector controls. The approved program order is unchanged; demo work and
later normative A2A/DID changes remain in their planned stages.

## Later approved-operation snapshot

The [approved-operation inspection](adk-approved-operation-inspection.md) adds
an explicitly selected query at ADK `fb98773df57b258c29ff9c355d062158bdf56c0e`.
It covers the new exact local policy, artifact snapshot and same-instance native
binding code with 49 reviewed anchors across 169 files. This historical query,
catalog and report remain unchanged, including their default CLI selection and
all deployment limitations. The new query does not attest a loaded provider or
select a Registry/host deployment.

The fifth [supervised child measurement snapshot](adk-child-measurement-inspection.md)
retains this historical query and separately checks the new private same-child
measurement channel. Its source matches do not close deployment obligations.

The sixth [admitted downstream capture inspection](adk-admitted-hop-inspection.md)
adds a separate exact revision for retained inbound originals, fresh local IDs,
current native parent/upstream rechecks, independent own issuance and existing
journal handoff. The five preceding catalogs/reports remain intact; the query
runs no ADK code and does not establish deployed or independent-hop conformance.
