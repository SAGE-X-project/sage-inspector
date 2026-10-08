# ADK supervised child measurement source inspection

This fifth explicit source snapshot pins `sage-adk`
`7eb69a8ef41ac5a36b01090411c14b833a5513ff` and preserves the SAGE 0.10.0
normative pin `1820ab5eafb843e1c13f4c46c34aeeb28d934ac9`. It reviews the
private `core/guardchannel` connection between the sealed child supervisor
and the compiled calculator measurement in that same child. This is a local
library integration, with no protocol, RFC carriage or wire change.

The [catalog](../verification/0.10.0/adk-child-measurement/catalog.json) hashes
182 tracked Go files excluding `_test.go`, plus both unchanged module files.
Compared with the fourth snapshot, only `core/guardimage/image.go` and
`image_linux.go` change; seven files are added under `core/guardchannel`.
Three implement the channel and four under `testdata/native` implement the
fixed safe calculator fixture and its providers/diagnostics. Source inventory
includes examples, generated sources, testdata and every build-tag variant.

The [saved query](evidence/adk-child-measurement.json) parses 1,238 declarations
and 6,020 syntactic calls, matching 105 manually reviewed boundaries. The first
59 rows remain unchanged. The fifteen preceding image/fixture rows are reviewed
against this revision, including changed declaration/call positions, inherited
fd 4 and delegated liveness. New rows cover 23 `CHILD_MEASUREMENT_OPT_IN`
boundaries, one `SEALED_IMAGE_OPT_IN` interrupted-pidfd boundary and seven
`RUNTIME_TEST_FIXTURE` boundaries. Totals are 15 sealed-image and eight fixture
rows. Ordinary builtin, Agent, Tool Registry, A2A and gRPC classifications stay
unchanged. Selected anchors are not an exhaustive effect or authority graph.

All four historical catalogs and reports are preserved byte for byte:
[routes](adk-source-inventory.md),
[approved operation](adk-approved-operation-inspection.md),
[compiled calculator](adk-compiled-calculator-inspection.md) and
[sealed executable](adk-sealed-image-inspection.md). Their statements describe
their pinned revisions; do not silently apply this fifth snapshot to them.
The historical route query remains the default. Registry preflight, mapping
and candidate provenance retain their separate pins and obligations.

## Reviewed boundaries

| Boundary | Manually reviewed behavior | Requirement outside this query |
| --- | --- | --- |
| `absent`, `enter`, `commitments`, `approved` | Typed-nil refusal; cancellation-aware serialization; core-validated commitments; exact copied unique artifact union covering the same approved image in both descriptors; bounded artifacts, descriptors, checks and time; private random generation. | Administration independently approves bytes, provenance and semantics. Constants/conditions are covered by whole-file hashes, not proven by selected calls. |
| `Start`, `Supervisor.serve` | Approve before sealed launch; fresh observation binds retained child PID once; exact next request/commitments/generation; fresh same-child observation before each acknowledgement; finite check budget and permanent retirement on failure. | Start establishes resource ownership, not accepted bootstrap or admission. Idle endpoint ownership lasts until Close; no positive cache approves work. |
| Linux `launch`, image Linux `start` | Exclusive private sequenced-packet socket pair with per-message credentials; sealed image is fd 3 and owned child socket fd 4; local child endpoint and failed parent endpoint close. | Isolated supervisor, native child, administration and descriptor custody. No caller replacement, path listener, signing service or unsigned tool dispatcher is added. |
| Linux `child`, `socket.bindPeer` | Child verifies fd/domain/type, captures real parent identity and sets/rechecks CLOEXEC; parent binds child PID exactly once from retained-process observation. | Per-message identity is not socket creation-time peer identity, logical worker/exec generation or remote attestation. Prevent descriptor theft and privileged credential impersonation. |
| `socket.wait`, `send`, `authenticate`, `receive`, `close` | Context-aware polling; bounded nonblocking records; one exact kernel-checked sender PID/UID/GID credential; truncated/foreign/missing/duplicate control refusal; close unsolicited descriptors; exact records only. | Protect handles and kernel behavior. An IPC acknowledgement is private appraisal, never transferable authority or native admission. |
| `OpenChild`, `establish`, `encode`, `decode` | Owned endpoint, mandatory Local provider, bounded closed bootstrap; fixed 112-byte B/Q/A records with generation, sequence and two commitments. | No signer, original request or Registry authority is carried. Local must establish actual protected loaded-code and isolation assurance. |
| `Measurement.Check` | One deadline starts before gate entry; exact approved child snapshot, mandatory Local check, next request and exact fresh acknowledgement. Panic, failure, mismatch or exchange cancellation retires without fallback. | Provider must honor its bounds and be non-reentrant. Child observation and later native admission are not atomic and do not exclude transient changes. |
| `Measurement.Close`, `Supervisor.Close` | Retire checks/observer, serialize accepted work, close own endpoint and retain owned-child cleanup through cancellation/retry. | Drain native effects first. Parent shutdown cannot atomically revoke already acknowledged accepted work; uncertain journals remain and cleanup proves no rollback. |
| `linuxProcess.live`, `pidfdLive` | Same owned nonnegative pidfd, at most three fresh zero-timeout polls, retry only EINTR; exit/readiness/other errors or exhausted interruptions refuse. | Process lifetime remains separate from native worker generation and reservation/final gate. |
| Unsupported `launch`, `child` | `ErrUnsupported`, supplied child file closed, no substitute launch or measurement. | Linux amd64/arm64 is a library candidate. Parsing build tags selects no production host. |
| `testdata/native` | Fixed same-child measurement/factory/private binding, real native encrypted loopback and verified arithmetic result, separately classified fixture Local/Registry and unchanged diagnostic delegates. | Local assurance and Registry are synthetic test providers, not production isolation, blockchain finality or deployment evidence. |

AST matching validates complete source/module hashes, exact declarations and
selected unique call locations. It does not prove call ordering, data flow,
type identity, runtime reachability, condition enforcement, isolation or complete
mediation. Nested callback calls belong to the enclosing declaration. External
dependencies, reflective dispatch and dynamic plugins are not resolved.

## Reproduction and refusal tests

Build only the trusted Inspector parser. Keep inspected source clean, quiescent
and at the exact reviewed revision:

```sh
go build -o /tmp/adk-source-inventory ./tools/adk-source-inventory
ADK_SYNTAX_PARSER=/tmp/adk-source-inventory python3 -B scripts/test_adk_source_inventory.py
python3 -B scripts/inspect_adk_source_inventory.py \
  --snapshot child-measurement \
  --adk-root /path/to/pinned/sage-adk \
  --parser /tmp/adk-source-inventory \
  --check docs/evidence/adk-child-measurement.json \
  --output /tmp/adk-child-measurement.json
```

Scenario units check exact history, source/module sets, new source hashes,
revision/catalog mixing, fixture separation and fabricated conformance fields.
Every selected channel, re-reviewed image and fixture declaration/call is tested
for removal and duplication. These synthetic AST units test refusal only.
Safe parser-CLI tests refuse unreviewed revisions for all five snapshots without
writing a report and parse inert initializers/callbacks without executing them.
CI reproduces all five saved reports from separate pinned checkouts and retains
query outputs as artifacts. Inspector runtime here is source parsing only.

Source and Git checks run before and after parsing; trusted quiescent storage
remains required. This is not isolation from concurrent hostile local writers.
A failed fresh query writes no new report; check exit status and do not reuse
an old output as a successful fresh observation.

The query runs no ADK child, native fixture, tool, model or plugin. ADK's safe
unit tests and real Linux amd64/arm64 child/native exchange tests remain separate
library evidence ([ADK PR 13](https://github.com/SAGE-X-project/sage-adk/pull/13)).
They use actual IPC, repeated executable observations and core admission with
fixture Registry and Local providers. They do not supply a selected protected
production host, authoritative blockchain Source or independent deployment
observations. No attack-capable reproduction or host-bypass program is added.

## Remaining work in the approved sequence

The same-child measurement connection is now available as an opt-in library
capability. Mandatory production Local loaded-runtime/isolation assurance and
native worker generation/reservation/final gate remain required. Do not measure
a parent calculator using a child observation; proc/backing-object checks are
not private instruction-page attestation, a sandbox or complete mediation.

Continue approved assembly: finish parent-hop binding separately, select and
bind authoritative blockchain Source and protected host configuration/providers,
then obtain independent effect/deployment observations. Preserve all nine gates
in the [remaining-work register](remaining-work.md), historical evidence and
later contract upgrade, demo and normative A2A/DID stages.

This source query is `AST_QUERY_EXECUTED`; ADK runtime in the query, all thirteen
deployed controls and independent hop execution remain `NOT_RUN`. Host selection
is `SELECTION_PENDING`, effect observations are absent and full conformance is
`NOT_ESTABLISHED`. No source match closes those deployment obligations.
