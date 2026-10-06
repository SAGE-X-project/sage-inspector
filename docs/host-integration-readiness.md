# Agent/MCP host integration readiness

This review prepares the first host integration decision after the
[external public consumer run](evidence/mcp-consumer.md). It does not select a
host or deploy one. The [source manifest](evidence/host-integration-readiness/manifest.json)
pins seven repository revisions, 42 relevant files and 18 source locations.
Tracked Go source inventories are also hashed for the ADK and gateway scans.
The frozen protocol remains 0.10.0 at
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`.

## Candidate comparison

| Candidate and revision | Existing responsibility | Remaining integration work | Disposition |
| --- | --- | --- | --- |
| `sage-adk` `6037298b49054ed6d1784ca1a28b6318b7dc310f` | Agent message context, configurable handler, builder and tool registry. | Update dependency/import compatibility; capture before message transformation/model work; independently authorize proposals; connect protected issuance, loaded instance, final dispatch and verified result. | Recommended **Agent integration candidate**, with preparation required. Not a working protected host. |
| `sage-gateway` `4e7266857676b338eb07d67673fbb5c4b275c263` | Sign outgoing HTTP requests and verify incoming requests before proxy forwarding. | Bind trusted original input and policy; use current role/freshness authorities; mediate the upstream effect and loaded component; persist execution/results. Its proxy boundary does not own those upstream responsibilities. | Useful HTTP/MCP integration candidate, with a different protection scope. |
| `sage-proxy-server` `eb7e9340d358bf5b2a32921b9a01d7a07cf6bcc6` | Only `LICENSE` is tracked. | No executable, dispatch or configuration to inspect. | No current host subject. |
| `sage-registry-service` `baf5570578ddc19685ebe2a5bda4a284f45c8e05` | Public Web Registry records and separate mTLS administration over one durable journal. | Select actual origin, certificates, clock/storage ownership and observer. Its Web Registry binding is not a blockchain deployment. | Registry **candidate**, independent of Agent host selection. |

The recommendation favors the ADK because the original message and tool
execution are Agent-owned responsibilities. The gateway can authenticate the
bytes it receives but does not independently establish what the user originally
requested or what a separate upstream process actually executes. Neither scan
found a `guard010`, `execution010`, `OpenCapturedClient`, `OpenMCPHost` or
`IntentIssuer` reference in tracked Go files. This source finding is not a
runtime bypass result or an exhaustive security audit.

## ADK preparation findings

1. `go.mod` replaces the Go core with `../../sage`; that directory is absent in
   the reviewed repository layout. It also uses a local `../sage-a2a-go`
   replacement. Updating these is a packaging decision and must pin compatible
   dependency versions rather than silently following a working directory.
2. `adapters/sage` imports legacy root paths such as `sage/core`,
   `sage/core/rfc9421`, `sage/crypto`, `sage/config` and `sage/did`. The reviewed
   current Go core places core, RFC 9421, cryptography and DID packages under
   `pkg/agent`; the old configuration import needs a separate mapping. Compatibility needs a deliberate source/API map; merely changing
   the module version cannot establish it.
3. The CLI assigns `defaultMessageHandler()`, which echoes `msg.Text()`.
   `Text()` selects the first text part, while the message exposes all parts.
   A protected original must retain the supported ordered input before that
   extraction, conversion or model work. A hash of the later echo/proposal is
   not the original capture contract.
4. The builder's SAGE and automatic server modes return `ErrNotImplemented`.
   The A2A server branch exists, but its adapter has placeholder reply methods
   and message conversion. None is a selected 0.10.0 MCP transport. This review
   does not redefine A2A wire behavior or advance the later A2A/DID stage.
5. `Registry.Execute` resolves a `Tool` and calls its `Execute` method directly;
   `Get` and `List` also expose tool objects. The future protected host must own
   the final supported effect path and its actual component instance. An
   optional call to a verifier in a message handler is insufficient evidence
   that all effect paths are mediated.

An offline `go list -e -mod=readonly -json ./cmd/adk` preflight was executed
with `GOPROXY=off`, `GOSUMDB=off` and `GOTOOLCHAIN=local`. It reported
`Incomplete: true`, the absent replacement and uncached dependencies. Because
`-e` can return zero while retaining dependency errors, its exit code is not a
successful build. Dependency caching was incomplete; no full compile result
or security verdict is inferred. No ADK executable, LLM or tool was started.

## Connection plan after host selection

The native libraries reviewed here are Go
`11b1cd91691de99fdbd734db78dc6755c187b2e9` and Rust
`cf3edb86a04e8ca0141b252c85e002c1f49bf9eb`. Their public issuer, native MCP
host and same-journal transfer entry points supersede the earlier private
assembly findings in [the original candidate assessment](agent-host-candidate-assessment.md).
The nine existing [host ports](host-port-inspection.md) remain the integration
contract; they are not new protocol obligations.

| Port | Required concrete host binding |
| --- | --- |
| `CaptureStore` | Exact supported ordered input and fresh request identity retained before transformations in protected storage. |
| `PolicyAuthorizer` | Independently selected policy epoch, approved component manifest and exact final arguments; model output is a proposal. |
| `IdentityAndReadiness` | Exact authoritative Registry Source, current active role-bound keys and readiness, including failure behavior. |
| `MeasuredComponent` | Approved hashes measured against the same loaded instance that owns the final supported effect. |
| `IntentSigner` | Protected issuer with one-use approval and durable issuance fence; credentials unavailable to model/plugin-controlled routes. |
| `TransportOwner` | Exact supported carriage/profile, bounded lifecycle, journal identity, cancellation and recovery; native length-framed MCP is not automatically HTTP or stdio. |
| `AdmissionLedger` | Exclusive durable ledger and reservation/execute/terminal ordering under the native owner. |
| `EffectOwner` | Inventory of supported effects and mediation at the final execution boundary; unsupported routes declared explicitly. |
| `ResultConsumer` | Current peer authority, exact request/result binding and verified terminal output before release. |

Implementation proceeds in this order after selection:

1. Map legacy imports and dependency replacements; establish a reproducible
   pinned build. Preserve explicitly named legacy scope and reject protected
   configurations that cannot be assembled.
2. Connect protected capture, independent policy, authoritative identities,
   approved loaded instance and isolated signing authority. Do not substitute
   fixture assertions for missing deployment providers.
3. Connect protected issuance and same-journal transfer to the selected native
   owner and final supported effect. Bind independently checked admitted-parent
   hop execution separately; the earlier root-only evidence does not close it.
4. Add unit scenarios and safe bounded runtime tests for the selected entry
   point, then pin executable/configuration, effect inventory, provider ownership
   and independent observer. Run the existing Inspector contracts against that
   subject. Potential attack-capable bypass reproduction stays outside runtime
   scope; scenario units cover those denial seams.

This is integration preparation within the approved core/consumer work. It
does not start the comparable demo stage, update normative wire rules, select
vendor hook behavior or claim that ordinary Agent callbacks isolate authority.

## Decisions and remaining evidence

The immediate decision is **ADK Agent integration or gateway/MCP integration
first**. A second, separate decision must identify the authoritative Registry
deployment and its Web or blockchain profile. An existing Web Registry service
cannot be counted as observation of the user's pre-registered blockchain
identity boundary.

Neither a pinned candidate revision nor the earlier inert consumer is a
deployed subject. Selection must subsequently bind the executable/configuration,
all claimed effect routes, trusted capture/policy/key/loader/storage/clock
providers and independent observer. All thirteen deployed host-port controls,
independent hop execution and deployed Registry evidence remain `NOT_RUN`;
full conformance remains `NOT_ESTABLISHED`.

The [approved program](https://github.com/SAGE-X-project/sage-spec/blob/1820ab5eafb843e1c13f4c46c34aeeb28d934ac9/architecture/program-sequence.md)
and [remaining-work register](remaining-work.md) retain their existing order.
Historical reviews and evidence keep their original pins and limitations.

## Pinned ADK execution-route preparation

The 2026-10-06 [ADK source route inventory](adk-source-inventory.md) pins
`sage-adk` `afa469cdd8539992185235008ac1591c74012f7f`. It parses all 163
tracked non-test Go files and checks 29 manually reviewed route anchors.
The opt-in native Guard owner is separate from capture-only Agent processing
and ordinary Tool Registry, Agent, A2A and gRPC callbacks. Signer/clock adapters
remain protected provider ports; model tool calls remain proposals. This
source query records those integration boundaries without running ADK or
closing any deployed-host control. It preserves the ordered work and historical
evidence above. Concrete policy, approved loader/final effects, authoritative
blockchain Registry deployment and a pinned inspected host remain outstanding.

The later [approved-operation inspection](adk-approved-operation-inspection.md)
pins ADK `fb98773df57b258c29ff9c355d062158bdf56c0e` separately. Its new local
helper binds independently selected exact rules and artifact snapshots to one
native instance. The source query checks 49 reviewed boundaries across 169
files while preserving the earlier report above. Actual loader attestation,
authoritative blockchain Source, selected final effects and deployed host
inspection remain outstanding; no deployed control or full conformance verdict
is changed.
