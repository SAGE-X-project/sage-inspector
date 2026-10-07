# ADK sealed executable source inspection

This fourth explicit source snapshot pins `sage-adk`
`1e70c58305edefdd302dea9b35c4a232f4c3e592` and keeps the SAGE 0.10.0
normative pin `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. It reviews
`core/guardimage`: bounded local supervision of an independently approved,
sealed Linux child executable. It changes no protocol or wire requirement.

The [catalog](../verification/0.10.0/adk-sealed-image/catalog.json) hashes
175 tracked Go files excluding `_test.go`, plus both module files. All 170
preceding source files and both module hashes are unchanged. Five files are
added: `image.go`, `image_linux.go`, `image_unsupported.go`, `maps.go` and
`testdata/host/main.go` under `core/guardimage`. The last file is a harmless
runtime fixture, not production integration. The source count deliberately
includes it because the inventory includes tracked non-test Go files under
`testdata` as well as examples, generated sources and every build-tag variant.

The [saved query](evidence/adk-sealed-image.json) preserves the preceding 59
reviewed rows and adds fourteen `SEALED_IMAGE_OPT_IN` boundaries and one
`RUNTIME_TEST_FIXTURE` boundary. It parses 1,174 declarations and 5,478
syntactic calls and matches 74 reviewed rows. Source matching does not show
that a deployment uses these opt-in capabilities. Direct builtin and ordinary
Agent, Tool Registry, A2A and gRPC routes retain their earlier classifications.

The [historical route query](adk-source-inventory.md) remains the CLI default.
The [approved-operation](adk-approved-operation-inspection.md) and
[compiled calculator](adk-compiled-calculator-inspection.md) snapshots retain
their exact pins. All three catalogs and reports are preserved byte for byte.
Registry preflight, mapping and candidate provenance reports keep their own
pins and outstanding obligations; the new ADK library does not close them.

## Reviewed boundaries

| Boundary | Manually reviewed behavior | Requirement outside this source query |
| --- | --- | --- |
| `active`, `acquire`, `Start` | Context-aware serialization, native Linux amd64/arm64 restriction, approved bytes before private platform startup. | Protected administration owns the capability; construction does not select or attest a deployed host. |
| `approved`, `staticGo` | Explicit 1–64 MiB bound, copied image bytes, approved SHA-256 comparison, native static ELF/Go profile, no dynamic/interpreter segment, executable stack or writable executable load. | Independently approve the baseline and build provenance. Go metadata restricts a profile; it does not prove origin or correspondence with policy semantics. |
| Linux `start` | One owned executable memfd, required write/grow/shrink/seal/exec seals, same sealed object's hash checked again before descriptor-based exec, empty environment, mandatory pidfd and owned child wait/failed-start cleanup. | Kernel support and protected launcher/host isolation. There is no mutable-path, PID-only or synthetic fallback. Call matching does not prove descriptor assignments, constants or condition enforcement. |
| `linuxProcess.live`, `observe`, `validMaps` | Retained pidfd liveness; proc executable device/inode/size/seals/hash agree with the owned object; bounded executable mappings must belong to it, with only named zero-inode kernel exceptions and no writable executable mapping. | Proc metadata is not live private instruction-page attestation, a sandbox, remote attestation or complete effect mediation. Process lifetime is not logical worker/exec generation; observations are not atomic with child admission and do not exclude transient changes. |
| `Process.Observe` | Serialized fresh appraisal, retained digest/native architecture/positive PID checks and permanent retirement after inconsistency, cancellation or concurrent retirement. | Supervisor, kernel/procfs and child must be isolated from untrusted writers. File sealing alone does not establish that isolation. |
| `Process.CheckSnapshot` | Exact policy and component commitments, exact image digest in both descriptors, verified owned artifact bytes and fresh child observation. | Child appraisal grants no native admission, parent-hop policy or peer approval. It is not `guardcalculator.Measurement` for a calculator in the parent; protected child-to-supervisor binding into the same child native gate is still required. |
| `Process.Close`, Linux `close` | Retire appraisal immediately, serialize cleanup, signal only the owned child through pidfd, await reap and close retained image/pidfd. Cancelled cleanup retains ownership for retry. | Retire native work and finish accepted effects before shutdown; retain uncertain journal completions after emergency termination. Successful cleanup never proves rollback. |
| Unsupported `start` | Return `ErrUnsupported` without launch or a substitute result. | All platform variants are parsed; source matching does not select a build target or demonstrate runtime support. |
| `testdata/host.main` | Fixed literal calculate command and fixed addition in an inert runtime test fixture. | No native Guard/admission exists in this fixture. It remains an unmediated test path, not a protected production route or deployment demonstration. |

These are manual reviews tied to complete source/module hashes, exact
declarations and selected unique call anchors. AST matching does not prove
ordering, data flow, type identity, reachability, condition enforcement or an
exhaustive effect graph. Unanchored constants/expressions still affect the
whole-file digest and require another reviewed snapshot when changed.
External dependencies and reflective/dynamic dispatch are not resolved.

## Reproduction and refusal tests

Build only the trusted Inspector parser. Keep the inspected checkout clean,
quiescent and at the exact sealed-image revision:

```sh
go build -o /tmp/adk-source-inventory ./tools/adk-source-inventory
ADK_SYNTAX_PARSER=/tmp/adk-source-inventory python3 -B scripts/test_adk_source_inventory.py
python3 -B scripts/inspect_adk_source_inventory.py \
  --snapshot sealed-image \
  --adk-root /path/to/pinned/sage-adk \
  --parser /tmp/adk-source-inventory \
  --check docs/evidence/adk-sealed-image.json \
  --output /tmp/adk-sealed-image.json
```

Units check byte-preserved history, exact source/module sets, fixture separation,
snapshot mixing and altered revision/hash/review/classification. Every new
selected declaration and call is tested for missing or duplicate anchors,
including sealed-object hashing before exec, pidfd/live object/mapping appraisal,
snapshot binding and retirement/cleanup. Fabricated AST scope cannot promote
conformance. Safe parser-CLI tests reject unreviewed revisions for all four
snapshots and parse inert initializers/callbacks without executing them. CI
reproduces all four saved reports from separate pinned ADK checkouts with the
Inspector-built parser and retains them as artifacts.

This query runs no ADK host, fixture main, tool, LLM or plugin. ADK's own safe
unit and Linux amd64/arm64 runtime tests are separate library evidence. They do
not supply actual native child admission, authoritative Registry mapping,
deployment attestation or an independent-hop execution result. No attack-capable
reproduction or host-bypass program is introduced.

Source checks run before and after parsing. Trusted quiescent storage remains
required; these checks do not isolate a concurrently hostile filesystem. A
failed fresh query writes no new report. Check process status and never reuse
an old output file as evidence of a failed invocation.

## Remaining work in the approved sequence

The source query is `AST_QUERY_EXECUTED`. ADK runtime in this query, all thirteen
deployed host controls and independent hop execution remain `NOT_RUN`; host
selection stays `SELECTION_PENDING`, effect observations are absent and full
conformance remains `NOT_ESTABLISHED`. The sealed child capability is available,
but a protected child-to-supervisor measurement connection bound to worker
identity/generation and final native admission remains outstanding. Do not
measure a parent calculator using a child observation.

Continue approved assembly in order: connect the same child calculator and its
native gate to protected supervision, finish parent-hop binding separately,
select and bind authoritative blockchain Source and protected host configuration,
then obtain independent effect/deployment observations. Preserve all nine gates
in the [remaining-work register](remaining-work.md), historical evidence and the
later contract upgrade and demo stages. Linux is a library implementation
candidate, not a selected production deployment.
