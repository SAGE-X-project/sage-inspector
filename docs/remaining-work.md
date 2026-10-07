# Remaining SAGE 0.10.0 work register

The [root capture core observation](core-root-capture-observation.md) records
the native Go/Rust Client import boundary and a later independent public
constructor parity run against exact revisions. The later
[signed captured Client parity run](evidence/captured-client-parity.md) checks
both public opening APIs and cross-core journal restarts. The
[signed result run](evidence/captured-client-results.md) also verifies output
consumption and terminal restart through those APIs. None changes a deployed-host
`NOT_RUN` verdict or closes the full-case gates below.

The [protected host-port inspection controls](host-port-inspection.md) now
link nine host responsibilities to 13 existing normative cases and pin the
unchanged source hashes. They report `NOT_RUN` without a versioned host;
matching bounded records remain `PARTIAL`. This inventory does not close the
later core, real Agent/MCP host, Registry Source or INS-11 gates below.

2026-10-03 first-stage closure: the
[design/Inspector tooling verdict](first-stage-completion.md) is
`TOOLING_READY` at `sage-spec`
`85fee1830b2bc0d2420557df40796ae83073de12`. It does not change the
historical implementation and deployment gates below. In particular, full
case execution, selected Registry Source and Agent-host observations,
INS-11, and organizationally independent review remain open in the approved
later stages.

The [first-stage readiness contract](first-stage-readiness.md) aligns this
technical register with the approved fourteen-stage program sequence:
`sage-spec` and Inspector design/test readiness come first. The nine gates
below remain ordered implementation and evidence obligations; their later
runtime and deployment results are not prerequisites for calling the first
stage's *tooling* ready, and tooling readiness is not conformance.

2026-10-03 addendum: the [current-core protected MCP-to-Guard policy
observation](guard-session-policy010-observation.md) passed 12 local runtime
cases, including denial after policy revocation. The
[Agent host candidate assessment](agent-host-candidate-assessment.md) identified
`sage-adk` as a possible integration consumer, not a selected or inspected
deployment. The nine ordered gates and all deployment `NOT_RUN` statuses below
remain unchanged. The counts and revisions in the following historical
snapshot are retained as of its stated date; later bounded observations do not
convert complete normative cases into `PASS`.

Status as of 2026-09-29. This register separates completed document and
Inspector tooling work from implementation, deployed integration and release
evidence. Its normative source is `sage-spec`
`44df132fee5925182018ce089dc82435cb353f8a`; the inspected cores are Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7` and Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`. The
[latest inventory](latest-spec-inventory.md) is the exhaustive case-level
register: **45 requirements, 91 rule groups, 489 parent cases and 26 mandatory
subscenarios**. All are `NOT_RUN` as *complete cases at that revision*.
Use `python3 -B scripts/latest_spec_evidence.py --output /tmp/latest-spec-evidence.json`
for every ID and status. Historical 386-, 457- and 481-case plans and their
revision-bound PASS/FAIL records remain separate; they are not added to 489.

## Current public API audit and next core changes

The [nine-port public API audit](evidence/host-public-api.md) records its
historical source review and external compiler observations. At those pins,
protected intent issuance was a source gap and coordinated non-HTTP MCP
owner/setup/admission assembly was internal.

The 2026-10-06 [protected issuance update](evidence/intent-issuance.md) pins
Go `d9d61d5d8daa9b2894ba6eddea2a771ccfe7ab54` and Rust
`eb0529922f2dd632357ceb1ed89eefb17cda9a29`. Both now expose protected root
and admitted-hop issuance, one-use approval and durable issuance fencing.
Four independently checked native root observations cover Go-to-Rust and
Rust-to-Go recovery and signing-failure fences. Native hop unit coverage is
separate; independent hop execution remains `NOT_RUN`.

The 2026-10-06 [public MCP host update](evidence/public-mcp-host.md) pins
Go `6a99b558a18d9c33ae9a07ce2ffa75af495661d0` and Rust
`cc83fba11d0e155d31af67dbdd840c9ab8cb0d9e`. Both now expose bounded native
owner/setup/admission/lifecycle assembly. External compiler checks and four
independently checked root TCP observations cover both same-core and cross-core
directions. This is `ROOT_MCP_TCP_INTEROP`, not deployed host certification.

The 2026-10-06 [external MCP consumer update](evidence/mcp-consumer.md) pins
Go `11b1cd91691de99fdbd734db78dc6755c187b2e9` and Rust
`cf3edb86a04e8ca0141b252c85e002c1f49bf9eb`. Separate external programs now
bind protected root issuance to public native MCP ownership using the same
durable Client journal. Four allowed directions and ten cross-core denials
are independently checked as `ROOT_EXTERNAL_CONSUMER_BOUND`. Registry,
clock, key custody and loaded component binding remain local fixtures;
this is not production loader or deployment evidence.

Within approved program stage 5, the next work is selection and pinning of an
exact Agent/MCP host and its protected capture, policy, authoritative registry,
key custody, immutable loader and actual effect services, then deployment
inspection. The [host integration readiness review](host-integration-readiness.md)
compares current ADK, gateway and Registry candidates and records the dependency,
capture, dispatch and provider preparation needed before a host can be inspected.
It recommends ADK as the Agent integration candidate but makes no selection;
the first host and authoritative Registry deployment are still decisions.
Independent hop execution remains `NOT_RUN` and must be bound
separately; root-only consumer evidence does not close it. Preserve every
broader gate below. No host is
selected, all thirteen deployed-host controls remain `NOT_RUN`, full
conformance remains `NOT_ESTABLISHED`, and demo work stays in its later stage.

## Ordered remaining gates

1. **Freeze and reconcile the 0.10.0 normative snapshot.** The coordinated
   standards/scope amendments have been written, but their exact-byte,
   accept/reject and interoperability consequences still require independent
   execution and review before claiming the design is fully validated. Check
   every chapter `spec/00` through `spec/11`, both MCP profiles, terminology,
   version and compatibility rules, error registry, traceability, vectors and
   change history together. Preserve the older snapshots and the separate
   design branch. `ADOPT-01..04` are resolved in the adopted/amended design;
   `ADOPT-05` linked evidence with scope limits; **`ADOPT-06` remains an
   organizationally independent external review gate**, despite the completed
   fresh-context LLM rereview. See the
   [adoption record](https://github.com/SAGE-X-project/sage-spec/blob/44df132fee5925182018ce089dc82435cb353f8a/verification/mcp-evidence-adoption.md)
   and [standards matrix](https://github.com/SAGE-X-project/sage-spec/blob/44df132fee5925182018ce089dc82435cb353f8a/verification/standards-application-matrix.md).
2. **Map every normative clause to both current cores and consumers.** Pin a
   clause-by-clause Go/Rust source and behavior map, identify implementation
   defects separately from specification ambiguity, and audit public imports,
   legacy paths and `sage/contracts/` before choosing strict APIs or moving
   packages. Existing [implementation-pattern review](https://github.com/SAGE-X-project/sage-spec/blob/44df132fee5925182018ce089dc82435cb353f8a/verification/implementation-pattern-review.md)
   is a bounded design review, not this complete gap map. Revisit the tracked
   document/Go AST graphs after changes and include the Rust and untracked
   surfaces when making repository-move decisions.
3. **Implement strict, usable Go and Rust 0.10.0 libraries.** Expose named
   protected entry points and host ports, then align exact bytes (L0),
   cryptographic/session verification (L1), trusted admission (L2) and complete
   Agent/MCP/gateway assembly (L3). Require clock, replay store, authoritative
   Registry Source, signing-key custody, policy, component loader and actual
   effect owner where the profile needs them. Preserve explicit legacy scope;
   no silent downgrade or substitute key/algorithm. Build both reusable
   libraries and verify their public ABI/API, errors, cancellation and state
   lifetime before SDK adoption.
4. **Close cryptographic and identity gaps in both cores.** Execute complete
   independent cases for JCS and signed-input rejection; strict Ed25519,
   supported ECDSA and key-role separation; registered HTTP `alg` and private
   non-HTTP suite boundaries; X25519/HPKE exporter, second-ephemeral
   contribution, transcript, acknowledgement and first-record confirmation;
   HKDF/session keys, nonce, sequence, replay, rekey and close; canonical DID,
   DID key URL and JWK projection. The [DID prefix run](did-prefix-observations.md)
   currently has **1 FAIL, 2 PASS, 3 UNSUPPORTED per core**, and the
   [wire/HTTP run](wire-http-binding-vectors.md) retains Go base FAIL and both
   full-boundary UNSUPPORTED. Close those measured gaps without changing the
   independent expectations merely to match an implementation.
5. **Complete transport, registry and Guard behavior.** Test RFC 9421
   request/response signature bases, `;req`, required components, digest over
   received content, header/parser/proxy behavior, key status, freshness and
   replay at a full receive/dispatch boundary. Cover HTTP, WebSocket and the
   pinned non-HTTP MCP binding only within their declared profile scope.
   Establish authoritative registry record/Card/PoP, activation, revocation,
   expiration, finality, stale/mixed-block and resolver behavior. Bind original
   user intent, approved tool arguments, loaded component hashes, policy
   epoch, durable reservation, one actual effect, signed result, restart and
   late completion in the trusted Agent/MCP host. Unit tests and safe bounded
   runtime tests are both required where feasible; attack-capable bypass
   reproduction remains excluded.
6. **Run all Inspector cases against exact revised implementations.** Port the
   older 481-case bindings and observations to the current 489-case source
   revision deliberately; implement full contracts for the eight new
   `msca-*` cases and execute all 489 parents plus 26 required children.
   Preserve per-case `PASS`, `FAIL`, `UNSUPPORTED`, `NOT_RUN` and `PARTIAL`.
   The eight current host contracts and this turn's primitive observations
   are partial evidence only. Rerun both directions of Go↔Rust handshakes,
   request/response, records, retries, replay, recovery and close on the same
   pinned profile and revisions. Existing INS-01..10 Inspector tooling is
   complete; **INS-11 is `INCOMPLETE`**, with full conformance
   `NOT_ESTABLISHED` (see [integrated verdict](ins11-integrated-verdict.md)).
7. **Bind and inspect real deployment authority.** Select and pin a Registry
   Source deployment (chain ID, RPC, address, bytecode/ABI hash, block/finality
   policy), then observe its actual state and failure modes. Select and pin an
   Agent host executable/configuration and independent effect observer; run
   its eight remaining host scenarios and the Go/Rust cross-core protected
   paths. Registry chain observation and the Agent-host scenarios are presently
   `NOT_RUN`; test doubles and core-local tests do not close them.
8. **Deliver the adoption repositories after core contracts stabilize.** Audit
   downstream importers, then split responsibilities under the
   [repository roles](https://github.com/SAGE-X-project/sage-spec/blob/44df132fee5925182018ce089dc82435cb353f8a/architecture/repository-roles.md): Go
   `sage` and `rs-sage-core`, language SDKs backed by built cores, trusted
   Agent/MCP/gateway integrations, registration/query backend, shared
   contracts if justified, CLI and comparable SAGE/no-SAGE demos/examples.
   Migrate or explicitly archive existing divergent SDK cryptography. Test
   packaging, cross-language byte/verdict parity, key custody, callbacks,
   cancellation, operational documentation and a comparable defended/residual
   risk demonstration. Physical moves follow library readiness and consumer
   audit, as specified by [migration gates 0–7](https://github.com/SAGE-X-project/sage-spec/blob/44df132fee5925182018ce089dc82435cb353f8a/architecture/migration-plan.md).
9. **Obtain independent and release evidence.** Commission organizationally
   independent protocol/crypto/MCP and implementation review (`ADOPT-06`),
   resolve findings in the correct spec→core→Inspector order, publish and
   dereference stable RFC 9457 problem-type URIs, check independent DID/JWK/
   HTTP/MCP consumers, and record deployment, performance, false-accept,
   false-reject and residual-risk evidence. Only then make versioned
   interoperability, security or release claims.

The [standards application matrix](https://github.com/SAGE-X-project/sage-spec/blob/44df132fee5925182018ce089dc82435cb353f8a/verification/standards-application-matrix.md)
has **22 source rows**, each with its own remaining verification column. The
rows cover RFC 2119/8174; 5234/7405; 4648; 8032; 7748; 6979; JWK RFCs
7517/7518/8037/8812; 8785; 9180; 5869; 8439; 9421/IANA algorithms;
9530; 8941/9651; 9110/9111; 9457; 6648; W3C DID Core/Controlled
Identifiers; W3C DID property extensions; W3C DID Resolution draft; CAIP-2;
and MCP 2025-06-18. `DESIGNED` or `REFERENCE` in that matrix is not a core,
consumer or deployed conformance verdict. Its 22 evidence obligations remain
covered by gates 4–9 above and must be checked row by row.

The previously excluded case where an attacker already controls initial Agent
DID/Card creation and blockchain registration is a **1.1 design question**,
not a hidden 0.10.0 completion criterion. The current 0.10.0 trust boundary
still requires protection and verification of later requests, messages,
component changes and effects even on a compromised endpoint when the
pre-registered identity was sound.

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
adds a separate ADK `fb98773df57b258c29ff9c355d062158bdf56c0e` source query.
It checks 49 reviewed anchors across 169 production files, including the exact
local policy/artifact/same-instance binding helper. The earlier source catalog,
report and all nine ordered gates remain intact. Concrete local binding code
is now available; protected actual loaded-code attestation, authoritative
blockchain Source details, selected host/effects and independent observation
remain outstanding. All deployed-host controls and independent hop execution
remain `NOT_RUN`; full conformance remains `NOT_ESTABLISHED`.

The [blockchain connection preflight](registry-contract-preflight.md) records
seven read/write/provider mapping obligations against the existing
`sage-contracts` revision `d9f313b1057d299423d800c846751ed40282a116` and the
same current core/ADK/normative pins. Exact exported ABI tuples, named keys,
whole-record versions, terminal state, proof/claim domains and actual provider
ownership require review before a blockchain Source can be connected. Its
query reads sixteen committed files without executing inspected code and does
not select a deployment or advance any conformance gate. Preserve the approved
later contract upgrade stage; do not change it or substitute Web authority to
make a missing binding appear complete.

The subsequent [Registry mapping review](registry-mapping-review.md) completes
bounded manual review of all seven source obligations on the same pins. It
records one reader mapping area, five write-semantics areas and one actual
provider area with 21 required evidence items. All six public-record
projections remain unbound, and reader-only conversion is insufficient.
Operator scopes/history and terminal state are explicitly included; no
contract upgrade or normative edit is performed. Source review completion
does not close deployment gates: no actual chain/host is selected, thirteen
host controls and independent hop execution remain `NOT_RUN`, and full
conformance remains `NOT_ESTABLISHED`. Preserve the nine gates and later
contract upgrade order above.
