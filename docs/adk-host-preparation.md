# ADK host assembly preparation

The first integration target is `sage-adk` at
`57f37e1c870d7bf1c5c6fdbd60efa1e62a6fcb6e`. This preparation narrows the first
host qualification effect to exact calculator addition, `2 + 3`, through the
private native length-framed MCP owner. This is an informative assembly plan,
not a new wire profile, runnable demo, selected deployment or execution grant.
The frozen SAGE 0.10.0 source remains
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`.

The [preparation query](../scripts/inspect_adk_host_preparation.py) reads the
exact clean ADK checkout, reuses the complete 444-file
[runtime source catalog](../verification/0.10.0/adk-runtime/catalog.json), and
checks thirteen manually reviewed source anchors. It does not build or run
ADK, a tool, model, plugin or contract. Hashes and unique text anchors bind
this review to source bytes; they do not prove semantics, call order, runtime
isolation or coverage of every effect route. Source checks before and after
report construction require trusted quiescent storage.

The [catalog](../verification/0.10.0/adk-host-preparation/catalog.json) and
[saved report](evidence/adk-host-preparation.json) preserve the nine required
host ports. All nine deployment bindings remain `NOT_BOUND`. This is a count
of preparation responsibilities, not nine new normative cases or the seven
Registry mapping areas/21 evidence items. The thirteen existing host controls
retain their original normative links and `NOT_RUN` status.

## Scope of the first host

The proposed qualification effect is one private compiled calculator instance,
independently approved exact policy/artifacts, and canonical arguments
`{"a":2,"b":3,"operation":"add"}`. It adds no shell, filesystem, network-fetch,
dynamic plugin or arbitrary tool capability. Actual policy, component bytes,
peer DIDs/keys, operation ownership and bounded host configuration must still
be provisioned and independently inspected before use.

The selected library route is `guardbinding.Open/OpenHop` and its private
instance binding, native `toolhost.Open/Serve`, final admitted `executor.Run`,
and captured-client terminal result consumption. Ordinary Agent callbacks,
Tool Registry, default ADK CLI handler, A2A, gRPC, HTTP MCP and stdio MCP are
outside this plan. Their presence does not acquire protection from opt-in
native construction. Later expansion needs an explicit route and authority
review. The ordinary CLI still uses a separate `defaultMessageHandler`.

Linux amd64/arm64 are the sealed-child launch candidates. The source query
itself runs on macOS. It neither executes a Linux binary on macOS nor treats
unsupported-platform refusal as a successful protected launch.

## Required assembly responsibilities

| Port | Available library boundary | Actual configuration/evidence still required |
| --- | --- | --- |
| CaptureStore | `capture.Host.Capture` and private file storage. | Trusted original ingress, protected directory/ancestors, capability ownership, plaintext retention and rollback policy. File modes do not isolate same-account code. |
| PolicyAuthorizer | Exact-operation `guardbinding.Operation.Authorize`. | Independently approved rules/evaluator/dependencies, durable policy epochs and lifecycle. Model output remains a proposal. |
| IdentityAndReadiness | Fresh Registry-bound signing authority. | Authoritative blockchain Source, finalized record/key/PoP mapping, code/ABI, readiness, freshness and failure policy. |
| MeasuredComponent | Mandatory `guardcalculator.Measurement` and same-child channel. | Actual loaded-runtime/dependency verification and protected local isolation; channel and sealed backing-file observations alone do not supply it. |
| IntentSigner | Registry-bound intent/result adapters and mandatory `Ed25519Backend`. | Actual immutable custody isolated from model/plugin routes; role-bound active key checks. A backend interface is not a deployed custody service. |
| TransportOwner | Exclusive native `toolhost.Serve` owner. | Authenticated endpoint generation/ownership, finite limits, cancellation/recovery and one shared monotonic origin. |
| AdmissionLedger | Native host ledger opening and core reservations. | Protected scope/history, serialization, recovery and close/uncertain-result ordering. |
| EffectOwner | Same private instance checked by final `executor.Run`. | Approved instance and exact arguments at the actual supported effect; no unsigned exported dispatch path in the selected host. |
| ResultConsumer | Captured Client reopening under the native connection owner. | Protected original Client checkpoint and journal transfer, fresh peer authority and exact verified terminal output before release. |

The ordered rows are an assembly responsibility checklist, not proof of a
runtime call sequence. System clock sampling exists but operating clock
accuracy/trust and restart policy remain deployment requirements. Native ADK
fixtures supply synthetic Registry and Local assurance. They do not close any
of these actual bindings.

## Reproduction and refusal checks

Saved-report checking runs without ADK execution:

```sh
python3 -B scripts/inspect_adk_host_preparation.py
python3 -B scripts/test_adk_host_preparation.py
```

For a fresh source observation, use the clean exact ADK revision and a new
output path:

```sh
ADK_PREPARATION_ROOT=/path/to/pinned/sage-adk \
  python3 -B scripts/test_adk_host_preparation.py
python3 -B scripts/inspect_adk_host_preparation.py \
  --adk-root /path/to/pinned/sage-adk \
  --check docs/evidence/adk-host-preparation.json \
  --output /tmp/new-adk-host-preparation.json
```

The scenario units refuse omitted providers/controls, fabricated readiness,
execution or conformance, expanded tools/carriage/platforms, changed ordering,
wrong revisions/hashes, source drift and untracked/ignored compiler inputs.
Safe CLI runtime tests check saved and fresh source reports, refusal without
a source checkout, missing source and exclusive output creation. They launch
only the Inspector query and Git readers, with no attack reproduction or
host-bypass program. CI supplies the exact source path so the fresh CLI test
runs rather than skips.

Exit zero means `HOST_PREPARATION_RECORDED` only. Every output still reports
`connection_authorization` and `dispatch_authorization` as `NOT_GRANTED`,
actual host execution as `NOT_RUN`, and full conformance as `NOT_ESTABLISHED`.
Without `--adk-root`, the query checks saved evidence and cannot create a new
observation. A failed fresh query cannot replace historical output. Check exit
status and never reuse an old file as a successful new observation. The JSON
is a review record, not a signed attestation or runtime authorization API.

## Next work in the approved order

Continue stage 5 host/provider preparation. The existing Sepolia address is
available as a read-only comparison candidate; its RPC declarations and code
identity cannot supply the unresolved normative read/write mapping or trusted
Source. Keep all seven Registry areas and 21 evidence items open until their
actual binding is established. Host configuration, custody/isolation, trusted
Source and independent effect observer remain decisions and evidence work.

This query changes no historical ADK report, complete-case status, INS-11 or
deployed-host verdict. A2A/DID/ERC-8004/KYA standards integration, contract
updates, demos, facilitator and Station stay in their approved later stages.
The research analysis and work method are separately stored in the user's
`study` project; no new normative feature is adopted by this preparation.
