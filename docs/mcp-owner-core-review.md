# MCP owner integration review

Decision: **NOT_READY_FOR_BINDING_IMPLEMENTATION** against the current core APIs.
This is a source-based integration review by the same author, not an external
independent security review, a normative adoption, or a finding that the existing
bounded Guard tests failed. The current primitives remain useful; a connection owner
cannot claim the proposed binding merely by wrapping their constructors.

## Fixed inputs

- Proposal: sage-spec `70abcda876879697cae91f1182ce5c9148211e8d`, copied in
  [the consolidated snapshot](../verification/0.10.0/mcp-consolidated-proposal/consolidated.md).
- Go: `be621819d8e4f3a51895ccf469617a0aa70ee81c`.
- Rust: `ad30c6ade287765ac96a500699469599b9696fcd`.
- Existing [dispatch evidence](guard-dispatch010.md), [RPC evidence](guard-rpc010.md)
  and [finite owner model](mcp-owner-model.md) retain their original scopes.

The review compares the proposal's final admission, callback publication and retained
history requirements with `DispatchGate`, `MCPEndpoint` and `MCPWireSender`. It does
not audit every core subsystem, live registry, cryptographic primitive or host.

## Blocking integration gaps

### 1. Durable execution state is not yet the proposed admission event

Both implementations reserve, persist EXECUTING, then recheck the signed intent,
current authority, component and time before the bounded component commitment:
[Go Dispatch](https://github.com/SAGE-X-project/sage/blob/be621819d8e4f3a51895ccf469617a0aa70ee81c/pkg/agent/guard010/dispatch.go),
[Rust dispatch](https://github.com/SAGE-X-project/rs-sage-core/blob/ad30c6ade287765ac96a500699469599b9696fcd/src/guard010/dispatch.rs).
Post-storage denial preserves UNKNOWN and prevents retry. That is intentional
conservative recovery behavior, not evidence of an unauthorized effect.

The proposal instead defines final admission as the durable EXECUTING transition,
preceded by final owner liveness/READY, invocation, authority and limit checks sharing
an order with close. The existing transition has neither that owner predicate nor
that interpretation. Treating its timestamp as the proposal's admission event would
misclassify denial/recovery traces. A wrapper cannot reach the private storage commit
to establish the missing ordering.

Required design: define an internal owner-aware admission operation at the gate,
including the storage failure and close linearization points. Retain post-storage
freshness checks where needed; moving all checks earlier would lose their protection
against storage delay. Specify what happens if authority or time becomes invalid
during persistence. Preserve conservative UNKNOWN recovery and never migrate existing
journal rows into proof of negotiated owner admission.

Acceptance evidence: final denial before admission, close before reservation, close
between reservation and admission, close after admission, and crash after admission
before effect. Use explicit scheduling seams and inert counters; measure both durable
state and actual bounded handoff. Include the four `mres-close-*`/crash cases from the
resolution plan, without claiming the whole case is executed until owner/session
bindings are real.

### 2. Endpoint closure waits behind the entire dispatch call

[Go MCPEndpoint](https://github.com/SAGE-X-project/sage/blob/be621819d8e4f3a51895ccf469617a0aa70ee81c/pkg/agent/guard010/mcp_rpc.go)
and [Rust MCPEndpoint](https://github.com/SAGE-X-project/rs-sage-core/blob/ad30c6ade287765ac96a500699469599b9696fcd/src/guard010/mcp_rpc.rs)
hold their session mutex while entering the gate. Close needs that same mutex. The
gate itself holds its mutex during trusted verification, storage and bounded component
callbacks. This serializes the existing API, but does not supply the proposed owner's
ability to record timeout/closure while callback work is pending.

Go context cancellation is cooperative and does not establish a shared owner-close
commit point; Rust dispatch has no equivalent cancellation argument. Neither fact
alone proves unsafe execution under the existing trusted bounded-callback contract.
It does mean that an owner must not implement its new cancellation semantics solely
by calling endpoint Close from a second thread.

Required design: separate revocation of owner admission rights from resource cleanup,
with a documented lock/transaction order shared by the gate. Do not hold an owner lock
across arbitrary callbacks, and do not reverse the endpoint-to-gate lock order through
a callback. Preserve the ability to store a result for an already admitted invocation.
Closing one owner must not globally retire a shared gate or erase another connection's
ledger. Worker cancellation and eventual cleanup require finite resource bounds.

Acceptance evidence: paused trusted work plus close/timeout, late completion, and two
owners sharing a gate where only one closes. Controlled pauses must have bounded
release and test timeouts; no hostile plugin, external tool or host bypass is needed.

### 3. Endpoint construction does not carry negotiated history

The same endpoint constructors accept a supported version string and a gate, then
create an empty request-ID set. They have no initialize/initialized/discovery state.
The source explicitly assigns negotiation provenance to the trusted host. The fixed
version and schema therefore remain compatibility checks, not proof of readiness.

The proposal requires one ID history spanning initialize, discovery and protected
calls. It also closes the owner on a repeated ID, exhausted history or invalid inner
message. Current Dispatch rejects duplicate/exhausted IDs and malformed input without
setting the endpoint closed flag on those paths. This is a difference from the new
binding, not a change to the older endpoint's documented contract.

Required design: the owner retains the single lifetime history and sole protected
routing path; avoid a second resettable endpoint history becoming authoritative.
Consume setup IDs in that history and preserve consumed outer replay state after
inner rejection. Decide the private endpoint integration contract before coding it;
do not expose an ImportReady or ResetHistory escape hatch.

Acceptance evidence: reuse an initialize ID after READY; reuse a discovery ID; endpoint
replacement on the same owner; malformed authenticated request followed by a valid
request; exhaustion including setup attempts. All must retain history and prohibit
new effects on the closed owner. A fresh authenticated owner may restart setup, while
Guard nonce, execution and client-consumption storage remain independent.

### 4. A synchronous sender result is not the output publication barrier

The current MCP sender interfaces perform one trusted synchronous handoff; the client
invokes its sender while serializing its own state. They do not contain the proposed
OUTPUT_PENDING state, one deferred wire frame, private operation/incarnation identity
or separate SETUP/PROTECTED deadline classes. An `Ok`/nil return cannot by itself be
used to publish READY without the proposal's final serialized checks.

Required design: keep preparation, bounded send and publication distinct. Synchronous
completion must be queued under the same rules as asynchronous completion. An old
callback cannot commit after close or attach to a replacement owner. Wire bytes must
be bounded before deferral; deferred input is authenticated only after successful
publication. Existing client/transport locks need an explicit non-reentrant integration
contract; spawning unlimited abandoned workers is not a timeout solution.

Acceptance evidence: response arriving before send returns, duplicate completion,
partial/uncertain send, deferred-frame overflow, close during output, exact setup
expiry, and protected output after setup deadline with its own valid deadline. The
finite models cover selected abstract schedules only; these require real owner APIs.

## Implementation order and adoption decision

| Order | Deliverable | Exit condition |
|---|---|---|
| 1 | Concrete admission/close and callback ownership contract | Resolve gaps 1–2, persistence-time invalidation and lock order without weakening current denial/recovery behavior |
| 2 | Normative reconciliation and independent review | Review the integrated proposal and concrete contract; explicitly update profile, pinned descriptor adoption, traceability and compatibility record together |
| 3 | Owner lifecycle and private gate integration in Go/Rust | One identity/history, operation deadlines and shared admission ordering; scenario units with deterministic scheduling and no external effects |
| 4 | Actual authenticated setup and protected flow in Inspector | Go/Go, Go/Rust, Rust/Go and Rust/Rust bounded exchanges; raw bytes, journals, handoff counts, closure order and callback identities preserved |
| 5 | Per-case protocol status update | Change only cases with complete actual bindings and observed assertions; retain every unrelated NOT_RUN |

Independent review remains NOT_PERFORMED. The proposal remains PROPOSAL_NOT_ADOPTED.
This review does not authorize a protocol release or silently reconcile the unpublished
local specification baseline. The next concrete work is the admission/close contract,
not another signature fixture or a declaration that the owner already exists.

## Verification of the existing behavior

Run the relevant current-core tests from their respective repositories:

```sh
go test -race ./pkg/agent/guard010 -run 'TestDispatch(FinalDenials|RetireAndReplaceOrdering|ConcurrentDuplicates)$' -count=1
cargo test --locked --lib guard010::dispatch_tests -- --test-threads=2
```

On 2026-09-21, the selected Go race tests passed and all 19 selected Rust tests
passed at the revisions above. These exercise real core code with trusted in-process fixtures, bounded inert handoffs
and temporary storage. They do not execute the proposed MCP connection owner or provide
network/host isolation evidence. No implementation behavior is changed by this review.
The 71 proposal cases and 37 historical lifecycle cases remain NOT_RUN; conformance
remains NOT_ESTABLISHED.

## Current implementation re-review

The blocking assessment above applies to its pinned Go `be621819...` and Rust
`ad30c6a...` revisions. At Go `8723075...` and Rust `8d91b2f...`, private owner-aware
admission, setup history, close tokens and protected reply publication are present.
The [current contract and source review](mcp-owner-admission.md) maps all four former
gaps to hashed implementation files and selected bounded core tests. Inspector runs
those tests from archived pinned commits and keeps their execution evidence separate
from source identity.

Passing that current contract closes the implementation prerequisites described in
gaps 1–4 for the pinned private paths. It does not change the historical result,
adopt the proposal as normative text, perform an external independent review, or
establish complete protocol and host conformance.
