# ADK host integration: unsupported boundaries

This register consolidates what the `sage-adk` host integration and the two
cores do not yet support or bind, after the separate-account qualification and
the 0.10.0 primitive observations. The frozen SAGE 0.10.0 source is
`1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. Revisions: ADK
`c660003025038ce086a22fbd3cc56152917f88a0` (Go core module
`6971de244ed87e0803f256d1616e22044d68afa8`), Go core
`6971de244ed87e0803f256d1616e22044d68afa8`, Rust core
`9294d17c3de54f36a239ee2318891b719a749631`. It adds no verdict: every status
below comes from the linked observation or source, and items without an
observation stay `NOT_BOUND` or `NOT_RUN`. The
[remaining work register](remaining-work.md) keeps the ordered gates.

## Host responsibilities

| Responsibility | Observed in this integration | Not supported or not bound |
| --- | --- | --- |
| CaptureStore | The receiver host verifies by provisioned mapping and holds no caller original ([qualification](adk-host-qualification.md), [mapping interop](evidence/receiver-mapping-interop.json)). | The caller's original ingress location, an OS boundary for capture paths beyond one run's per-account directories, and a plaintext retention and deletion policy are not selected. |
| PolicyAuthorizer | Exact-operation rules approved and signed by an operator ledger; the caller refuses unapproved arguments before issuance. | The operator key is generated per run. Durable operator key custody and rotation and a deployed policy epoch lifecycle are not selected. The refusal observed is the caller's issuance policy, not a receiver-side refusal. |
| IdentityAndReadiness | None. | `NOT_BOUND`. The Registry Source is a local JSON file whose readiness flags are asserted. No blockchain Source exists in either core or ADK, and the 21 Registry mapping items stay open. |
| MeasuredComponent | None. | `NOT_BOUND`. The calculator measurement accepts any snapshot; no Local provider binds the loaded runtime or its isolation. |
| IntentSigner | A separate signer process under another account serves signatures over a Unix socket after a peer-credential check ([qualification](adk-host-qualification.md)). | All accounts share one kernel. This is not hardware custody, attestation or sandboxing. |
| TransportOwner | Signer processes hold the Ed25519 and X25519 KEM keys; the receiver holds neither ([KEM custody report](evidence/adk-host-qualification-kem-custody.json)). | The signer returns one X25519 shared value per handshake, so a compromised receiver can derive that session's secrets; custody protects the long-term key only. Since ADK `c660003` the caller opens an initiator-only core host and signs no results ([initiator-only report](evidence/adk-host-qualification-initiator-only.json)); the receiver still opens a full host by design. |
| AdmissionLedger | The native ledger runs in per-account state directories; ADK recovery tests cover restart paths. | A protected storage location, its owning account and an operational recovery procedure are not selected. |
| EffectOwner | The executor re-verifies admission and intent before the compiled `2+3` calculator runs. | No selected production host executable or effect exists beyond the inert calculator. |
| ResultConsumer | The caller verifies the signed result (`{"output":5,"success":true}`). | A protected Client checkpoint location and original Client ownership outside the qualification run are not selected. |

The host clock refuses any backward step. Docker Desktop for macOS cannot host
the run for that reason; the GitHub `ubuntu-24.04-arm` runner observed none.
An operational clock accuracy and restart policy is not selected.

## Deployed and host-dependent cases

- The thirteen deployed host controls linked by the
  [host-port inspection](host-port-inspection.md) remain `NOT_RUN`.
- The ten host-dependent EXEC parent cases in the
  [host boundary gaps](current-spec-host-boundary-gaps.md) remain `NOT_RUN`;
  they need a versioned Agent or executor host adapter.
- Full conformance remains `NOT_ESTABLISHED`.

## Core and Inspector coverage of the frozen design baseline

The [saved 0.10.0 primitive observations](evidence/design-baseline/primitive-010/)
cover 74 of 489 parent cases per core (73 `PARTIAL`, 1 `UNSUPPORTED`). The
other 415 are `NOT_RUN` for these reasons:

| Parent cases | Reason |
| --- | --- |
| 245 | Runtime fixtures for operations that other bridges observe (Registry 60, transport 31, Guard sequences 27, session 26, DID resolution 26, HPKE handshake 21, card 20, host trace 15, HTTP boundaries 9, others 10). They have revision-bound current-spec records, not design-baseline observations. |
| 132 | Host-case fixtures that need a versioned host. |
| 16 | `sage.http.verify`: both generic adapters answer without calling the core, citing the missing injected clock and complete boundary API. |
| 19 | Document-review or deployment-review contracts with no runtime fixture. |
| 3 | Evidence-review fixtures. |

Matching fixtures reach `PARTIAL` only, because the prior fixture contracts are
partial; no parent case reaches `PASS`.

## Core API boundaries

- HPKE-03-N01 is `UNSUPPORTED`: the 0.10.0 derivation rejects an all-zero
  X25519 value internally but exposes no standalone exchange. The general Rust
  primitive `X25519KeyPair::diffie_hellman` returns the all-zero value without
  error; it is not a 0.10.0 entry point.
- The strict 0.10.0 DID parser exists only in current cores; CI jobs pinned to
  older cores build the 0.10.0 profile without it, and DID validation is then
  `UNSUPPORTED`.
- Legacy APIs with no 0.10.0 replacement stay outside 0.10.0 observations:
  general RFC 9421 signing and verification, network DID resolvers, legacy key
  proof-of-possession and A2A card proofs (Go
  `docs/LEGACY_010_DEPRECATION.md`, Rust `docs/legacy-010-deprecation.md`).

## Evidence nature

Saved reports are review records, not signed attestations. A log fabricated in
its entirety can satisfy format checks; CI re-runs reduce but do not remove this
limit. Observations are bounded local processes or one runner, not deployed
hosts.
