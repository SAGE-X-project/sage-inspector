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

2026-10-09 addendum: the [ADK host unsupported boundaries](adk-host-unsupported-boundaries.md)
consolidate what the separate-account `sage-adk` host integration and the
0.10.0 primitive observations of both cores leave unsupported or unbound,
including the reason for each of the 415 design-baseline parent cases that
remain `NOT_RUN`. It changes no verdict and closes none of the gates below.

2026-10-10 addendum: the [core refactoring and ADK host integration verdict](core-host-integration-verdict.md)
is `BOUNDED_CORE_HOST_INTEGRATION` at Go core `4e4ca2c`, Rust core `2ee96e9`
and ADK `c7890e1`. IdentityAndReadiness and MeasuredComponent stay `NOT_BOUND`,
deployed controls stay `NOT_RUN` and full conformance stays
`NOT_ESTABLISHED`; it closes none of the gates below.

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

The 2026-10-08 [admitted-worker child issuance observation](evidence/hop-issuance.md)
pins Go `1aaee98258e72aeeaba5a8c49fc9908b41ff29cd` and Rust
`cf3edb86a04e8ca0141b252c85e002c1f49bf9eb`. Four same-core/cross-core
root exchanges and six own-provider refusals independently bind exact native
parent admission to B's protected child issuance. Its child journal has no
transmission or result; `HOP_ISSUANCE_BOUND` does not close independent full
hop execution, Registry/host selection, the thirteen deployed controls or any
complete normative case. The previous source inspections and runtime artifacts
retain their original bytes and verdicts.

The 2026-10-08 [native protected hop execution observation](evidence/hop-execution.md)
adds actual three-process A-to-B-to-A exchanges at those same core pins. All
eight Go/Rust combinations and eight ordinary refusal observations bind child
transmission, one inert leaf execution, signed child-result consumption and
signed completion/denial output back to the root Client. Its verdict is
`LOCAL_NATIVE_HOP_EXECUTION_BOUND`. Registry, custody, component, clock and shared
parent-context acquisition remain explicit local fixtures. Bootstrap recovery
uses real signed native exchanges; the independent full outer-handshake oracle
remains `NOT_RUN`. This report supplies bounded local hop evidence while
preserving the prior issuance-only report and every deployment/full-case gate.

The 2026-10-08 [pinned ADK test execution observation](adk-runtime-observation.md)
adds fresh race-enabled execution at ADK
`57f37e1c870d7bf1c5c6fdbd60efa1e62a6fcb6e` with the public Go core module at
`f1a840bbc9c717564bd035e19c73f437a61e4a00`. Its three reviewed groups execute
56 top-level tests and 257 leaf tests, including 25 safe native runtime fixtures.
`PINNED_ADK_TESTS_PASSED` closes this selected test-execution observation only.
Native hop bindings remain co-located with synthetic measurement/Registry
providers; this is not an independent protocol oracle or a deployed host.
All seven source snapshots and the separate core hop observation are preserved.
The actual Registry/host choices, 21 mapping requirements, thirteen deployed
controls, full-case and release gates below remain in their approved order.

Within approved program stage 5, the next work is selection and pinning of an
exact Agent/MCP host and its protected capture, policy, authoritative registry,
key custody, immutable loader and actual effect services, then deployment
inspection. The [host integration readiness review](host-integration-readiness.md)
compares current ADK, gateway and Registry candidates and records the dependency,
capture, dispatch and provider preparation needed before a host can be inspected.
It recommends ADK as the Agent integration candidate but makes no selection;
the first host and authoritative Registry deployment are still decisions.
Deployed independent hop execution remains `NOT_RUN` and must be bound
separately; the bounded local hop observation does not close it. Preserve every
broader gate below. No host is
selected, all thirteen deployed-host controls remain `NOT_RUN`, full
conformance remains `NOT_ESTABLISHED`, and demo work stays in its later stage.

The 2026-10-08 [ADK host preparation](adk-host-preparation.md) now fixes the
first integration target at ADK `57f37e1c870d7bf1c5c6fdbd60efa1e62a6fcb6e`
and records one exact harmless calculator qualification effect over the native
owner. Its query checks the complete 444-file source pin and thirteen reviewed
anchors, preserving all nine required provider bindings as `NOT_BOUND`. This
is an assembly preparation, not a selected executable/configuration or an
execution grant. Every existing deployed host control remains `NOT_RUN`, all
21 Registry mapping evidence items remain open, and complete-case/INS-11/full
conformance statuses are unchanged. Ordinary CLI/Agent/Tool Registry and other
carriages remain outside this opt-in host plan; actual trusted providers and
independent deployment observations are the next work in the approved order.

The 2026-10-09 [separate-account host qualification](adk-host-qualification.md)
runs the assembled ADK hosts at `ccc053c898ac83d741c7f667efe48c964f6b7532` with
Go core `7e8a0790d57ae709f8efee237db94bd4995d65ee` on a Linux arm64 runner. Two
signer processes, a receiver without the caller's original, a caller and a test
operator run under five accounts; the approved `2+3` call is verified, unapproved
arguments are refused by the caller's policy and no wall-clock step occurs.
`SEPARATE_ACCOUNT_QUALIFICATION_OBSERVED` covers that run only. Its Registry
Source and calculator measurement are synthetic, so IdentityAndReadiness and
MeasuredComponent remain `NOT_BOUND`; the KEM key stays in the receiver process
and the accounts share one kernel. The thirteen deployed host controls remain
`NOT_RUN`, all 21 Registry mapping items stay open and full conformance remains
`NOT_ESTABLISHED`.
A later observation at ADK `8111a00c964c9db3c7be4580fbe5308d4f8505b5` keeps the
receiver's X25519 KEM key in a signer process as well, so the receiver holds no
private key; it adds a fourth isolation check and changes no other status.

The [receiver mapping interop observation](receiver-mapping-interop.md) runs four
Go/Rust native MCP exchanges at Go `e6c40f4bddb457702810c1058eaf863bd31293ec` and
Rust `4f691b3526063e74c4408bef9abfa998cbaf4c0d` in which the receiver verifies
through its provisioned `(issuer, policy_digest)` mapping and holds no usable
original. `RECEIVER_MAPPING_MCP_TCP_INTEROP` covers those exchanges with local
fixtures only; deployed host controls stay `NOT_RUN`.

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

The [Sepolia candidate provenance observation](registry-candidate-provenance.md)
adds a dated read-only diagnostic for the unselected README candidate. Its
RPC-returned code equals the two runtime bytecode fields published by Sourcify;
the published ABI equals the pinned 64-entry ABI. Four of five compared
production source files equal the current contract pin, while the Registry
file matches an older blob and differs by one KEM initialization line. These
are retrieved-record comparisons, not independent recompilation, trusted
finality, complete deployed-source equivalence or SAGE conformance. No Source
or host is selected, no mapping evidence is closed, and all ordered gates,
historical reports and later contract upgrade requirements remain intact.

The [compiled calculator source inspection](adk-compiled-calculator-inspection.md)
adds a third explicit ADK snapshot at `1da9d02226bd690f92ccc4198638afc84579a9e8`.
Its 170 production files and 59 reviewed boundaries include mandatory measurement,
closed calculator configuration, same-instance compiled arithmetic and retirement.
Direct builtin use remains unmediated. The previous two source reports and
Registry mapping pins stay intact. Source matching supplies no protected
pre-load/runtime measurement provider, authoritative blockchain Source binding
or deployed host/effect evidence. All thirteen deployed controls and independent
hop execution remain `NOT_RUN`; full conformance remains `NOT_ESTABLISHED`.
Continue the approved assembly and deployment gates in order, retaining the
separate later contract upgrade and demo stages.

The [sealed executable source inspection](adk-sealed-image-inspection.md) adds
an explicit fourth snapshot at `1e70c58305edefdd302dea9b35c4a232f4c3e592`.
It parses 175 tracked non-test Go files, including one harmless testdata host,
and matches 74 reviewed boundaries. Fourteen new boundaries cover the bounded
Linux child supervisor; the test host is separately classified as an unmediated
runtime fixture. The three preceding catalogs/reports and all Registry review
pins remain intact. Sealed executable backing-object/proc metadata appraisal
is available, but it is not instruction-page attestation, a sandbox or a
measurement provider for a parent calculator. Protected child-to-supervisor
binding into the same child native gate, worker generation/final admission,
parent-hop binding, authoritative Source and isolated host/effect observation
remain outstanding in the existing order. All thirteen deployed controls and
independent hop execution remain `NOT_RUN`; full conformance remains
`NOT_ESTABLISHED`. This snapshot selects no production host and does not begin
the later contract upgrade, demo or normative A2A/DID stages.

The [supervised child measurement source inspection](adk-child-measurement-inspection.md)
adds the fifth explicit ADK snapshot at
`7eb69a8ef41ac5a36b01090411c14b833a5513ff`. It parses 182 tracked non-test Go
files and matches 105 reviewed boundaries, including 23 private child-measurement
boundaries, bounded interrupted pidfd polling and seven separately classified
native runtime fixture boundaries. The first 59 route rows and all four previous
catalogs/reports are preserved; changed image rows are re-reviewed at the new pin.
The same-child supervisor connection to compiled calculator/native admission is
available as a library integration. Production child-local loaded-runtime/isolation
assurance remains mandatory and unbound; the IPC generation is not logical worker
or exec generation, observations are not atomic with admission and shutdown is not
rollback. Continue parent-hop assembly, authoritative Source and selected protected
host/providers, then independent effect/deployment observations in the existing
order. All thirteen deployed controls and independent hop execution remain
`NOT_RUN`, full conformance remains `NOT_ESTABLISHED`, and no later contract,
demo or normative A2A/DID stage is started by this source review.

The [admitted downstream capture inspection](adk-admitted-hop-inspection.md)
adds the sixth explicit ADK snapshot at
`e2653847e7d75507e1561e36baebcf321ca3307c`. It parses 183 tracked non-test Go
files and matches 119 boundaries, preserving all five historical catalogs/reports
and their 105 route rows. Seven new hop boundaries, three metadata-only rows and
four retained policy/signing wrappers distinguish current actual parent checks,
fresh local original, independent own policy/signing and native existing-journal
handoff with no history recreation. Library capture/issuer/handoff is available;
`guardbinding.Open` remains root-only. Continue concrete independently approved
hop-operation/loader assembly, then authoritative Source and selected protected
host/providers, then independent effect/deployment observations in the existing
order. Query runtime, thirteen deployed controls and independent hop execution
remain `NOT_RUN`; full conformance remains `NOT_ESTABLISHED`. Neither this query
nor ADK's separate fixture-based one-core runtime tests close deployment gates
or begin later contract, demo or normative upgrade stages.

The [approved downstream operation inspection](adk-approved-hop-inspection.md)
adds the seventh separate snapshot at ADK
`57f37e1c870d7bf1c5c6fdbd60efa1e62a6fcb6e` and Go core dependency
`f1a840bbc9c717564bd035e19c73f437a61e4a00`. It matches 122 ADK boundaries
across 183 source files and seven ordered-clock/liveness core boundaries across
244 source files. Six historical catalogs/reports remain unchanged. Separate
`OpenHop` now binds actual retained parent to independently approved local
policy/artifacts and immutable loader; roots retain null-parent approval.
Core timer/protocol sampling shares ordered local-clock history while final
current-key/time/liveness gates remain required. Separate safe same-core
runtime evidence uses co-located bindings and synthetic providers. Continue
authoritative blockchain Source and selected protected host/providers, then
independent effect/deployment observation in the approved order. Query core/ADK
runtime, all thirteen deployed controls and independent hop remain `NOT_RUN`;
full conformance remains `NOT_ESTABLISHED`. Later contract, demo and normative
upgrade stages are not started by this source review.
