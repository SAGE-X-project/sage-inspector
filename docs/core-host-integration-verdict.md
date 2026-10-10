# Core refactoring and ADK host integration verdict

**Verdict: `BOUNDED_CORE_HOST_INTEGRATION`.** This closes stage 5 of the
[approved program sequence](https://github.com/SAGE-X-project/sage-spec/blob/85fee1830b2bc0d2420557df40796ae83073de12/architecture/program-sequence.md):
Go `sage` and Rust `rs-sage-core` expose the protected 0.10.0 entry points
that a separated host needs, and `sage-adk` assembles them into caller and
receiver hosts observed under separate accounts. It is not a deployment,
Registry, measurement or full conformance verdict. Two host responsibilities
stay `NOT_BOUND` by decision, the thirteen deployed host controls stay
`NOT_RUN`, the integrated INS-11 verdict stays `INCOMPLETE` and full
conformance stays `NOT_ESTABLISHED`.

The normative source remains `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`,
bound by the [first-stage verdict](first-stage-completion.md) at `sage-spec`
`85fee1830b2bc0d2420557df40796ae83073de12`. Revisions at this verdict: Go core
`4e4ca2cdaa80a30e20d4c3fc9f2ad727f66e5f73`, Rust core
`2ee96e9a54955625a6da90bad1927e6bb711819d`, ADK
`c7890e1ba4438d74e2a0b4684f8575d3e5df53a9` (Go core module
`v1.5.3-0.20261009164347-40809355bd4d`). Each saved observation below keeps
its own pinned revisions; nothing here re-labels older evidence.

## Exit evidence

The program sequence asks stage 5 for five kinds of evidence. Each is listed
with what supports it and where it stops.

**Importable protected entry points.** ADK imports the Go core as a module,
and its `verification/library-consumer` check builds a separate consumer module
against the same pinned core module version. The cores added the APIs a
separated host needs: signing and X25519 KEM custody callbacks for the handshake endpoint (Go
`NewCustodyCompletionEndpoint010`, `NewProtectedCompletionEndpoint010`; Rust
`CompletionEndpoint010::new_protected`), receiver-side intent verification by
provisioned mapping without the caller's original (Go `NewReceiverPolicy`,
Rust `ReceiverPolicy`), an initiator-only MCP host that opens no admission
gate, ledger, executor or result signer (Go `OpenMCPClientHost`, Rust
`MCPHost::open_client`), and canonical manifest bytes under the manifest
limits (Go `guard010.CanonicalManifest`, Rust `guard010::canonical_manifest`).
The Rust crate is library-buildable; no Rust host consumer exists yet.

**Cross-language parity.** The [receiver mapping interop](receiver-mapping-interop.md)
runs Go→Go, Rust→Rust, Go→Rust and Rust→Go protected MCP exchanges whose
receiver holds no caller original, checked by an independent oracle. The
[0.10.0 primitive observations](evidence/design-baseline/primitive-010/) give
identical case statuses for both cores. Earlier captured Client, signed result
and hop observations listed in the [remaining work register](remaining-work.md)
keep their own revisions.

**Unit and safe runtime checks.** Each core change merged with its CI. The
[separate-account qualification](adk-host-qualification.md) runs the assembled
hosts on a GitHub `ubuntu-24.04-arm` runner under five accounts in three
saved observations: the first assembly, signer-held KEM keys, and an
initiator-only caller. In each, the caller's policy refuses unapproved
arguments before issuance and the approved call returns the verified output
`{"output":5,"success":true}`. ADK CI keeps statement coverage of the host
assembly, signer and approval packages at 90% or more.

**Explicit unsupported boundaries.** The
[unsupported boundary register](adk-host-unsupported-boundaries.md) lists,
for each of the nine host responsibilities, what was observed and what is not
supported or bound, and gives the reason for every design-baseline parent case
that remains `NOT_RUN`.

**Version-pinned Inspector results.** Every observation above names exact
subject and runner revisions, and its workflow rebuilds and re-runs the pinned
subjects. A local re-run of the 0.10.0 primitive profile against the Go and
Rust revisions of this verdict produced the same outcome for every case as the
saved observations (73 `PARTIAL`, 1 `UNSUPPORTED`, 415 `NOT_RUN` per core). That
re-run is not saved evidence.

## Carried forward

| Item | Status | Where it continues |
| --- | --- | --- |
| IdentityAndReadiness | `NOT_BOUND` by decision. The Registry Source is a local file with asserted readiness flags. | Stage 8 updates `sage-contracts` and adds a real Source. |
| MeasuredComponent | `NOT_BOUND` by decision. The calculator measurement accepts any snapshot. | A selected Local provider; not scheduled in stage 5. |
| Thirteen deployed host controls, ten host-dependent EXEC parents | `NOT_RUN`. They need a versioned deployed host. | Later deployment stages. |
| 415 design-baseline parent cases | `NOT_RUN` for the reasons in the boundary register. | Other bridges and a versioned host. |
| Rust custody and initiator-only host | Core tests only. ADK is a Go host. | A Rust host consumer, if one is selected. |
| Session secrets after KEM custody | The signer returns one X25519 shared value per handshake, so a compromised receiver can derive that session's secrets. | Moving decapsulation behind the signer needs a core API change. |
| Legacy APIs with 0.10.0 replacements | Marked deprecated in both cores with reasoned lint exceptions for intended legacy callers. | Removal follows each core's version policy (Go not before v1.8.0). |

## What this permits

Stage 6 may build its demo on these cores and the ADK host. The demo inherits
every limit above: a synthetic Registry Source, an accept-all measurement,
account separation on one kernel and loopback transport are not a protected
deployment, and a measured defended behavior in the demo is not a universal
security claim.

## Evidence nature

Saved reports are review records, not signed attestations, and the
observations are bounded local processes or one CI runner. A later normative
change reopens the baseline and requires new observations before any
implementation claim.
