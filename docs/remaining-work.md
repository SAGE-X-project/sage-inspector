# Remaining SAGE 0.10.0 work register

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
