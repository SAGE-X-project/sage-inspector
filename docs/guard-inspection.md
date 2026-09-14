# Execution Guard inspection for 0.10.0

Inspector preparation now includes 102 independent primitive/boundary cases and
37 persistent scenarios (297 steps), a combined execution/report command, mutation
tests, and explicit CST-01..05 fixture links. Real Guard dispatch remains untested
until a protected state adapter exists. This is not host-isolation certification.

## Current subjects and results

| Subject | PASS | FAIL | UNSUPPORTED | Stateful scenarios |
|---|---:|---:|---:|---|
| Go c7709b7486e0da94336edc0931fddd87f6a45343 | 8 | 0 | 94 | 37 NOT_RUN |
| Rust 206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2 | 8 | 0 | 94 | 37 NOT_RUN |

Both bundles are INCOMPLETE. The eight passes are four JCS and four signature
projections using existing core APIs. They are not eight successful Guard executions.
No EXEC profile implementation was found in the pinned core source trees, and no
missing policy, ledger or dispatcher was implemented inside a core adapter.
See [evidence/guard](evidence/guard) and its provenance for exact inputs, source
hashes, binary identities and observations. No core source was changed.

## Independent primitives and operation contracts

[generate_guard_vectors.py](../scripts/generate_guard_vectors.py) uses public
fixed Ed25519 test keys, Python cryptography and SHA256, without SAGE imports.
[check_guard_vectors.js](../scripts/check_guard_vectors.js) independently recomputes
commitments/signing bytes and uses Node Ed25519 verification. The source fixtures
use ASCII object member names and safe integers; broader JCS/curve cases remain
prerequisites in the existing suites. Positive and invalidly bound, re-signed
messages distinguish semantic policy rejection from merely broken signatures.

| Operation | Input and asserted result |
|---|---|
| sage.guard.original.commit | Ordered items expressed as exact UTF-8 hex or bounded repeated-byte recipes; return original_digest. Test single versus bundle, whitespace, composed/decomposed Unicode, empty item, 1024/1025 items and 1MiB/1MiB+1 aggregate bytes. No normalization. |
| sage.guard.manifest.verify | Closed manifest and exact artifact path/bytes pairs; return manifest_digest. Check path traversal, empty/dot components, absolute paths, backslash/NUL, ordering, duplicate paths and changed hashes. This checks fixture bytes, not a remote filesystem. |
| sage.guard.policy.commit | Closed descriptor; return policy_digest after shape/manifest/epoch/engine/bounds checks. Reproduce the published CST-02 commitment e70a2dfb…8bdb. 2044 two-member file entries fit the descriptor's aggregate member bound; 2045 exceed it. Descriptor validation is not administrative approval or proof of complete dependency coverage. |
| sage.guard.json.bounds | Expand prefix_hex + repeated byte + suffix_hex into actual JSON bytes. Check 1MiB/1MiB+1, root-container depth32/33 and aggregate object members4096/4097. This is the resource-bound projection, not full intent/result schema acceptance. |
| sage.guard.intent.verify | Raw signed envelope, trusted clock/key/peer, provisioned policy/manifest, protected original commitment and closed read-tool schema. Validate full field set, recipient, original, current policy approval, tool/arguments, nonce/digests, signature and time. Unknown/recursive tools, extra/missing/mistyped arguments, wrong policy/manifest/key binding, invalid parent and changed signature fail. |
| sage.guard.result.verify | Raw signed result, exact tracked intent envelope, active executor key, trusted time and outstanding invocation. Validate identity/digest/time/status/output before consumption. Pending/rejected/unknown have empty output. An already accepted invocation may return a freshly signed result after intent expiry; a new retrieval may not start then. |
| sage.guard.mcp.result | structured result envelope plus canonical text and isError; require agreement, no additional block, and isError false only for completed. This mapping projection assumes result verification; it does not authenticate an unsigned wrapper by itself. |

All non-digest/schema projections return `{valid:true}` on acceptance. Rejection
has empty output. The repeated-byte recipes construct actual bytes before the
subject boundary; declared sizes are not accepted as evidence. Expansion bounds
are at most 1048577 bytes for a single original item/JSON document and at most1025
original items. The suite itself stays inside schema1's 4MiB transport limit.
Policy and manifest file digests cover exact bytes; only canonical JSON is hashed
for their aggregate commitments. The manifest hash does not contain a domain
prefix, while policy, original, intent and result domains are separately fixed.

Full signing relationships/fresh registry facts and administrative mappings enter
through protected test seams, not message-supplied authority. The fixed evaluator
allows the named read tool with exactly a string path; it is not an LLM prompt.
Disabling user confirmation never disables those required gates. Human-semantic
agreement with a prompt is not established by any fixture's signature.

## Persistent state and effects

[guard_scenarios.py](../scripts/guard_scenarios.py) authors expected state only.
It is never installed as a reference or core adapter. The independent Node model
replays those expectations and verifies the setup/recovery envelope signatures.
It caught a mutable-reference error during authoring; every emitted expected
snapshot is now copied, and corruption tests check state/effect drift explicitly.
Neither model is evidence of real locking, storage durability or protected effects.

`control.guard.setup` provisions exact original/recovery intent envelopes, policy,
manifest and public artifact bytes, fixed signer responses, key identities, an
intact durable test ledger, an immutable artifact instance `artifact-A`, and optional
outstanding Client invocation IDs. Signer fixtures are deterministic callback
outputs for persistence/reuse testing, not authority a peer may provide. A real
binding must observe callback calls and bytes; it cannot copy expected counters.
Initial authorization/active-identity checks are controlled as valid unless a
scenario explicitly injects their failure. Real cryptographic/schema rejection is
covered separately by the raw-envelope cases.

| Action | Required boundary and observation |
|---|---|
| submit | Run authentication/current authorization and exact-envelope lookup. Absent call reserves call ID and nonce atomically; identical retries return a pending or stored terminal snapshot without dispatch. Fresh invocation IDs are separate from durable call identity. |
| reject | Persist a no-dispatch terminal rejection and nonce atomically for an absent call. An existing reservation/execution cannot be overwritten. A later submit retrieves that rejection; it never dispatches. The controlled policy-denial decision is injected after authentication and before this transaction. |
| dispatch | Recheck current policy, clock/expiry and measured instance at the protected commit gate; dispatch the stored verified argument object exactly once to artifact-A. |
| complete | Persist the first terminal outcome and exact signed envelope atomically before any publication. Persistence/signing failure cannot claim completed. No second response is pushed to the original invocation. |
| crash | Preserve the execution ledger and mark unresolved RESERVED/EXECUTING entries UNKNOWN. Never redispatch. UNKNOWN receives its one stored signed envelope when the trusted signer becomes available and cannot become completed later. |
| lose-ledger / recover | Distinguish lost state from an intact empty ledger. Recovery requires trusted administration, synchronized affected scope, retirement of all old commitments, a durable new mapping and a never-used epoch. An unused UUID or partial rollout alone is rejected. Old signed calls remain rejected after successful recovery; a newly authorized envelope can execute. |
| retire | Serialize retirement with dispatch and invalidate pending authorization. Already committed effects are retained and may finish; retirement is not rollback. A RESERVED internal record can remain in the ledger while its policy_active flag makes it unusable. |
| measure | Inject changed/unknown loaded artifacts at the actual measurement/load seam. Matching a hash before reopening a different instance must not suffice. |
| gate-failure | Inject skipped, timed-out, failed or disconnected enforcement, direct-call or signing-oracle attempts. Required outcome is no protected effect. This is a binding contract; actual host bypass attempts are separate work. |
| client-result | For an outstanding invocation, consume the first verified terminal envelope once, ignore an identical terminal or delayed verified pending, reject conflicts/unsolicited/unverified responses and never reopen the operation. |
| client-poll / client-new-call | Enforce at least one second between polls and stop at terminal/intent expiry. A new call ID solely to bypass UNKNOWN is denied. This cadence is a Client requirement, not a fabricated receiver rejection of every concurrent retry. |
| inspect | Return exact durable entry digest/state/arguments/terminal digest, ledger integrity, active approved policy, measured/clock flags, dispatch arguments/instance history and consumed Client terminal digest. |

REJECT in the Inspector action contract means that local action was denied or no
trustworthy response could be produced. It must not be confused with publishing a
signed `result.status=rejected`. Existing execution state must survive failed reads.
A broken proof is explicitly an authentication failure; the separate changed-valid-
intent and nonce-collision fixtures have valid newly computed signatures, so they
exercise call/nonce identity rather than using signature failure as a substitute.

Effects are cumulative reservations, dispatch, protected signed responses, result_signatures,
consumed and polls. Recording exact dispatch arguments and instance IDs is required;
zero counters must be observed at the protected seam, not invented. The persistence-failure fixture injects failure before terminal preparation/signing begins; it does not require all possible storage failures to have zero signing attempts. Missing storage,
clock, policy, signer or dispatcher instrumentation returns UNSUPPORTED and stops
subsequent steps as NOT_RUN.

`subject.parallel` starts real concurrent operations and holds them before the same
protected commit gate, then releases the specified gate_order. The order makes
race outcomes reproducible: retire-first gives no dispatch, dispatch-first preserves
one effect; rejection-first produces a durable rejection, reservation-first cannot
be overwritten. Duplicate workers share the same durable store and effect sink.
Do not implement this contract as a serial loop or wait at a barrier while holding
the core's exclusive lock. The authoring models simulate order only; no actual race
or multi-process/replica exclusion is claimed by their audit.

## CST linkage and security boundaries

[guard-closure-links.json](../vectors/0.10.0/guard-closure-links.json) records exact
fixture hashes/IDs for CST-01 pending/retry/terminal semantics, CST-02 policy
commitments/retirement/recovery, and prior session fixtures for CST-03 AAD bounds,
CST-04 participant/key binding and CST-05 provisional confirmation. The combined
report verifies referenced files without merging unrelated results into Guard PASS.
These are representative readiness links, not a claim that all386 planned cases or
all28 closure scenarios executed. Session confirmation still does not grant execution
permission; a denied tool can follow an authenticated session record with zero effects.

Physical immutable-load protection, a signing-key boundary outside replaceable
plugins, interception of file/network/subprocess/subagent paths, replica durability,
transactional external effects and host capability isolation require actual bindings
and deployment evidence. They are not proved by hash equality, self-reported flags,
DID registration or network signatures. Hardware/remote attestation and whole-host
compromise or semantic-prompt safety are not advertised. Optional host verifier tools
remain diagnostics; no missing verdict permits a protected call to fall back.

## Run and interpretation

```sh
go build -o /tmp/sage-conformance ./cmd/sage-conformance
go build -o /tmp/sage-scenario ./cmd/sage-scenario
node scripts/check_guard_vectors.js
python3 scripts/test_guard_inspection.py
python3 scripts/inspect_guard.py --runner /tmp/sage-conformance \
  --adapter /absolute/core-adapter --subject sage-go --revision ACTUAL_REVISION \
  --output-dir /new/evidence-directory
```

Supply both `--scenario-runner /tmp/sage-scenario --state-adapter /absolute/guard-adapter`
when the protected binding exists. Existing output directories are not overwritten.
Membership, hashes, subject identity, expectations, effects and process exit status
are verified. Exit0 PASS,1 FAIL,2 ERROR,3 INCOMPLETE. Lack of an implementation
cannot become a false success. Inspector preparation is complete; real Guard
conformance remains explicitly open for the cores/host integrations.
