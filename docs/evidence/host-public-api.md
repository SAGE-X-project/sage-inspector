# Public core API audit for the nine host ports

This audit checks whether an external Go module or Rust crate can name the
reviewed host integration APIs. The generated consumers compile against Go
`8c29b785e36fe8f7d7dc9e55bd9deb036df0088f` and Rust
`c99d373b772a3fb33e166fda3e07ee7ba94414f0`. Their inert executables emit the
nine port names; they do not create an Agent, sign an intent, dispatch an effect
or establish a network session. Separate compiler probes confirm that the
internal Go `newMCPHost` and Rust `mcp_transport::Host` are not importable.
Unrelated compiler failures do not count as that observation.

The result is `PUBLIC_API_ACCESSIBILITY`. It is **compilation evidence**, not
runtime behavior or a complete protocol-case `PASS`. The dedicated protected
intent issuance route is `NOT_RUN`, a deployed host remains `NOT_RUN`, and full
conformance remains `NOT_ESTABLISHED`. Existing signed Client runtime evidence
is preserved separately in the [capture](captured-client-parity.md) and
[result](captured-client-results.md) reports. No host-port control is promoted.

The [catalog](../../verification/0.10.0/host-port/public-api.json) contains the
exact reviewed declarations, source file hashes, host obligations and gaps.
The [machine report](host-public-api.json) pins the catalog, existing thirteen
host controls, and generated compiler probe hashes. The conceptual names come
from the existing host-port contract; cores need not export those literal names.

| Host port | Public Go / Rust seam | Assessment and remaining obligation |
| --- | --- | --- |
| CaptureStore | `NewRootCapture`, `OpenCapturedClient` / `RootCapture::new`, `Client::open_captured` | Public commitment and Client primitives. The host still captures before expansion, generates fresh IDs and protects durable original input. |
| PolicyAuthorizer | `IntentPolicy`, `PolicyCommitment` / `IntentPolicy`, `policy_commitment` | Public evaluator callback. The host supplies local policy, epoch, exact target/arguments and one-use approval. Verification success alone is not execution authority. |
| IdentityAndReadiness | `Authority`, `NewRegistryAuthority` / `Authority`, `RegistryAuthority::new` | Public authority callback and registry binding. Actual authoritative source, key custody and readiness are host duties; coordinated MCP setup and close remain internal. |
| MeasuredComponent | `VerifyManifest`, `Component.Check` / `verify_manifest`, `Component` | Public measurement primitive and trusted component callback. The host binds the same immutable loaded instance and dependencies; a file hash alone is insufficient. |
| IntentSigner | No dedicated protected intent issuance API in the reviewed Guard surface | Source review gap. Existing APIs receive already signed intent; result signing does not issue client intent. Generic signing cannot supply authorization, one-use decision, peer binding or protected journal identity. |
| TransportOwner | `ClientSender`, `NewMCPClientSender`, `MCPEndpoint`, session carriage helpers / corresponding public traits, structs and helpers | Public handoff and carriage primitives. Coordinated non-HTTP MCP host, owned client and setup assembly remain internal. These primitives alone do not establish authenticated owner lifecycle. |
| AdmissionLedger | `OpenLedger`, `OpenDispatchGate` / `GuardLedger::open`, `DispatchGate::open` | Public generic reservation and dispatch gates. The MCP owner admission bridge remains internal; storage protection and exclusive host lifetime remain integration duties. |
| EffectOwner | `Component.Commit`, `Invocation`, `Completion` / `Component`, `Invocation`, `Completion` | Public trusted effect callback and gate-bound tokens. The host must mediate its complete effect inventory and isolate capabilities. |
| ResultConsumer | `VerifyResult`, `Client.Accept`, gate result publication / `verify_result`, `Client::accept`, gate result publication | Public verifier and durable Client consumption primitives. Host journal protection and actual output release still require deployment evidence. |

## Ordered follow-up within the approved core refactor

1. Define and implement a protected intent issuance entry point in both cores.
   Bind captured root or admitted parent, locally selected issuer/recipient,
   exact final tool arguments, manifest and policy epoch before key use. Require
   role-bound active Ed25519, one-use authorization and protected operation
   identity; do not turn an arbitrary signing callback into a model-facing API.
   Verify denial cases with unit tests and bounded ordinary runtime exchanges.
2. Stabilize a public non-HTTP MCP assembly around the existing private owner,
   setup, readiness, admission and close coordination. Exporting private structs
   mechanically is insufficient: ownership, cancellation, retry uncertainty,
   recovery and lifetime must remain enforced at the reusable entry point.
3. Bind the host-supplied capture, policy, registry, immutable loader and effect
   callbacks in an external consumer, then inspect that exact executable and
   its claimed routes. The host selection decision follows these API contracts.
   ADK remains a candidate; this audit does not select or launch it.

These follow-ups belong to approved program stage 5. They do not reopen the
normative design, start the later demo stage, or replace the wider
[remaining-work register](../remaining-work.md). Callback obligations are
integration requirements, not evidence that the core must implement a universal
policy language, loader or operating-system sandbox.

## Reproduction

Use clean, pinned core checkouts and previously fetched public dependencies:

```sh
python3 -B scripts/inspect_host_public_api.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --output /tmp/host-public-api.json
cmp docs/evidence/host-public-api.json /tmp/host-public-api.json
python3 -B scripts/test_host_public_api.py
```

The existing captured Client CI job repeats this compilation audit against
both exact core revisions. Without core paths, the script validates only the
saved report and does not execute the compilers.
