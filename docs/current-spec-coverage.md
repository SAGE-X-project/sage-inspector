# Current 0.10.0 specification coverage

The current inventory is pinned to `sage-spec` revision
`5bcf511e604579afa63f434013447f44b6858828`. It contains 45 requirements,
91 rule groups, 481 parent cases and 26 mandatory subscenarios. The previous
386-case INS-01 snapshot and its evidence remain historical. They are not
rewritten or counted as observations of this revision.

`scripts/current_spec_catalog.py` verifies the current traceability snapshot,
every requirement-to-rule and rule-to-case relationship, the 386 historical
case classifications, 95 additional case classifications, all mandatory
subscenario parents, and hashes of every normative source file cited by the
rules, the MCP tool descriptor, and the standards-clause audit. `MOWN-06` is
a cross-case mandatory-child mapping rather than a rule
with its own parent cases. CI checks these identities against the pinned
`sage-spec` checkout. New or removed cases, changed source files, and
reclassified historical cases require an explicit catalog update.

Run the inventory locally with:

```sh
python3 -B scripts/test_current_spec_catalog.py
python3 -B scripts/current_spec_catalog.py \
  --spec-root /path/to/sage-spec \
  --report /tmp/current-spec-inventory.json
```

The report enumerates all 481 cases and their applicable verification tracks.
Its statuses are `NOT_RUN` and its conformance verdict is `NOT_ESTABLISHED`.
The inventory answers whether Inspector knows every normative case. It does
not answer whether a Go or Rust core, MCP host, Registry Source, or deployed
system passed that case. In particular, related primitive vectors and rule
IDs are not complete parent-case evidence.

The gap report distinguishes the 386 baseline cases, 71 earlier MCP cases,
eight Registry clarification cases, and 16 later correction cases. Only eight
baseline cases have related primitive prerequisites; these do not establish
complete case coverage. Generate it with:

```sh
python3 -B scripts/current_spec_gap.py --output /tmp/current-spec-gap.json
```

`scripts/current_spec_evidence.py` is the case-level evidence admission and
status engine. Its 335 current bindings cover selected JCS, HTTP, HPKE,
session, DID, Agent Card, transport, and Registry cases only partially; the remaining cases still need bindings. A binding must name a current
case or mandatory child, one required verification track, a repository-owned
fixture hash, and whether that fixture covers the complete case or only part
of it. An external observation must pin the spec revision, exact fixture and
input hashes, subject repository/revision/executable hash, runner revision,
environment, and typed verdict/output/effect counters. The engine compares
the independently stored expectation with the observation; it does not accept
a self-reported `PASS`. Missing bindings and observations remain `NOT_RUN`,
reported lack of subject support is `UNSUPPORTED`, an observed mismatch is
`FAIL`, and a matched partial fixture is `PARTIAL`. Every required track and
mandatory child must pass before a parent case can pass. Even then overall
conformance remains `NOT_ESTABLISHED` until the separate integration gates
are satisfied.

```sh
python3 -B scripts/test_current_spec_evidence.py
python3 -B scripts/current_spec_evidence.py \
  --evidence /path/to/revision-bound-observations \
  --output /tmp/current-spec-evidence.json
```

The unit tests use synthetic, inert observations to check status derivation.
They are not evidence that a SAGE implementation passed a normative case.
`scripts/run_current_spec_cases.py` can execute bound runtime fixtures against
one explicit local adapter. It sends the case input but never the expected
answer, bounds the process, and writes hashed observations for the evidence
engine. Document and deployment reviews use their own observation capture;
they cannot be replaced by a primitive adapter. An attempt to run a case
without a reviewed runtime fixture fails explicitly. The primitive bridge
translates the seven JCS parser cases to the existing Go/Rust core adapter request,
preserving raw JSON bytes and returning only the core verdict. Its
empty effect map means effects were not observed; this is partial case evidence.
For JCS-02, the bridge submits both signed Guard intents and records the
control and candidate verdicts from the receiving schema path.
The first [Go/Rust JCS observation](current-spec-jcs-evidence.md) records one
Go mismatch and one Rust partial match. The expanded
[JCS parser observations](current-spec-jcs-parser-evidence.md) record all six
parser scenarios. The [signed integer observations](current-spec-jcs-integer-evidence.md)
record five JCS-02 scenarios using valid signed controls without promoting
overall conformance.
The [canonical-byte observations](current-spec-jcs-canonical-evidence.md)
record four JCS-03 byte relations against both cores, also as partial cases.
The [proof-exclusion observations](current-spec-jcs-exclusion-evidence.md)
record four JCS-04 Agent Card cases as `UNSUPPORTED` because neither current
core adapter exposes the 0.10.0 card verifier.
The [HTTP signature observations](current-spec-msg01-evidence.md) add five
MSG-01 cases. They preserve a Go signature-base mismatch, a Rust partial
match, and the unavailable full-profile verification boundary.
The [HTTP component observations](current-spec-msg02-evidence.md) add six
MSG-02 cases, distinguishing digest and missing-header primitive checks from
receiver-endpoint and version-policy checks unavailable in current adapters.
The [request-bound response observations](current-spec-msg03-evidence.md)
add five MSG-03 cases. Their signed control reuses the independently verified
MSG-02 request and records which response checks remain unavailable.
The [HTTP receiving-boundary observations](current-spec-msg04-evidence.md)
add six MSG-04 cases with exact duplicate, framing, byte-limit, and resolver
conditions. Current adapters cannot establish rejection or zero protected
effects for those full-boundary cases.
The [freshness and replay fixtures](current-spec-msg05-evidence.md) add six
MSG-05 cases with exact timing, rotated-key nonce reuse, concurrent copies,
and lost-state quarantine. The current core adapters cannot observe the
HTTP freshness boundary, while older real journal evidence covers only its
storage dependency.
The [HTTP failure-handling fixtures](current-spec-msg06-evidence.md) add four
MSG-06 cases. A signed application-failure response can be checked with
current RFC 9421 primitives; generic 401 routing and the protected
result-consumption boundary remain outside the current core adapters.
The [HPKE suite and key-role fixtures](current-spec-hpke01-evidence.md) add
four HPKE-01 cases. A published Base exporter answer is executable in both
cores; suite rejection and active signing/KEM key admission require the
complete handshake boundary.
The [HPKE initiation-binding fixtures](current-spec-hpke02-evidence.md) add
five HPKE-02 cases. They bind the exact B/info/exportCtx bytes to a current
exporter result and reserve authenticated identity, context, nonce, and key
selection denials for the complete initiation verifier.
The [HPKE transcript and combiner fixtures](current-spec-hpke03-evidence.md)
add five HPKE-03 cases. They check the exact transcript hash and session seed,
zero shared-result handling, and isolated transcript and ephemeral mismatches.
The [HPKE completion fixtures](current-spec-hpke04-evidence.md) add five
HPKE-04 cases. They bind the signed completion domain to a current Ed25519
verification result and preserve ACK, pending-request, and handle denials for
the complete completion boundary.
The [HPKE provisional-state fixtures](current-spec-hpke05-evidence.md) add
five HPKE-05 cases. The first initiator record is executed against current
record cryptography; confirmation, deadline, retransmission, and restart
decisions still require a stateful handshake boundary.
The [HPKE admission fixtures](current-spec-hpke06-evidence.md) add five
HPKE-06 cases for the exact payload limit, malformed fixed field, unsigned
cookie, and secret-free diagnostic boundary. Current primitive adapters do
not expose full handshake admission or its effect and log instrumentation.
The [session identity fixtures](current-spec-session01-evidence.md) add four
SESSION-01 cases and four related CST-04 tuple cases. The current core
record export exposes the transcript-derived public session ID in both
directions; participant, role, and bound-key decisions still require a
stateful receiver boundary.
The [session key and lifetime fixtures](current-spec-session02-evidence.md)
add five SESSION-02 cases and one related CST-05 case. Both cores can be
observed opening independently computed records across generation boundaries
and rejecting sequence 1000; lifetime and policy decisions require stateful
instrumentation.
The [record-format fixtures](current-spec-session03-evidence.md) add six
SESSION-03 cases and two related CST-03 AAD cases. The current cores directly
open or reject bounded records, while complete transport projection and
protected dispatch still require a receiver boundary.
The [send-allocation fixtures](current-spec-session04-evidence.md) add four
SESSION-04 cases for concurrency, transport failure, retransmission, and
legacy MAC exclusion. Both primitive adapters lack the necessary stateful
transport operations, so those cases remain `UNSUPPORTED`.
The [replay and reordering fixtures](current-spec-session05-evidence.md) add
five SESSION-05 cases. A separate retained-core run observes three
record-layer partial matches; concurrent acceptance and a valid 1024-slot
window overflow remain unverified. The primitive case reports keep all five
as `UNSUPPORTED` because they cannot expose retained receive state.
The [session closure fixtures](current-spec-session06-evidence.md) add six
SESSION-06 cases. A separate retained-core run observes rejection and empty
output after explicit record-session close. Fresh handshake, registry,
expiry, restart, and transport fallback boundaries remain unverified.
The [DID syntax fixtures](current-spec-id01-evidence.md) add six ID-01 cases.
Both cores reject the current canonical web DID and accept a forbidden kind
alias. Valid-control pairs prevent other blanket rejections from counting as
matches; key URL fragment validation remains unavailable.
The [registry identity fixtures](current-spec-id02-evidence.md) add four
ID-02 cases. Neither primitive adapter exposes registry identity comparison;
both reject a canonical chain DID and accept the forbidden `eth` alias.
Canonical controls keep the alias and uppercase-address mismatches visible.
The [named-key fixtures](current-spec-id03-evidence.md) add six ID-03 cases.
Both primitive adapters lack full registry authentication, so they remain
`UNSUPPORTED`; a separate retained-core run confirms ten limited key-state
prerequisites without promoting signature or sender verification.
The [registry lifecycle fixtures](current-spec-id04-evidence.md) add four
ID-04 cases. The current mutation API is absent in both cores, so all four
remain `UNSUPPORTED`; a separate safe core run confirms the unsupported
response leaves the local journal unchanged.
The [Agent Card schema fixtures](current-spec-card01-evidence.md) add six
CARD-01 cases. The source card's signature and an isolated 65,537-byte
boundary are checked independently, while both primitive adapters report
the complete card-verification operation as `UNSUPPORTED`.
The [Agent Card proof fixtures](current-spec-card02-evidence.md) add five
CARD-02 cases. Generic signature primitives in both cores distinguish the
required domain from a wrong domain, but do not enforce the SAGE proof type
or registry key binding; full card verification remains `UNSUPPORTED`.
The [Agent Card freshness fixtures](current-spec-card03-evidence.md) add five
CARD-03 cases. An unchanged signed card is compared against expiry, a newer
record version, an inactive record, and a changed service endpoint. Both
core adapters lack full card verification, so all five remain `UNSUPPORTED`.
The [transport envelope schema fixtures](current-spec-transport01-evidence.md)
add five TRANSPORT-01 cases. Generic signature verification accepts their
correctly signed bytes, including four invalid-schema envelopes, while both
core adapters lack the full envelope verifier and remain `UNSUPPORTED`.
The [whole-request signature fixtures](current-spec-transport02-evidence.md)
add five TRANSPORT-02 cases. Both cores' generic signature primitives reject
recipient, payload, and metadata mutations but accept a re-signed key URL
owned by another DID; full request verification remains `UNSUPPORTED`.
The [response binding fixtures](current-spec-transport03-evidence.md) add
seven TRANSPORT-03 cases. Their response signatures are valid in both core
signature primitives, but complete response-to-request and terminal-state
verification remains `UNSUPPORTED`.
The [receive and replay scenarios](current-spec-transport04-evidence.md) add
five TRANSPORT-04 cases. Declarative unit checks cover the reservation
expectations, and both cores reject an isolated failed-tag record. The
combined receive transaction remains `UNSUPPORTED`.
The [HTTP dual-signature scenarios](current-spec-transport05-evidence.md) add
four TRANSPORT-05 cases and nine static variants. Both cores verify the 16
present signatures as primitives, but neither exposes the integrated HTTP
receiver, so joint acceptance and effects remain `UNSUPPORTED`.
The [WebSocket and local receive scenarios](current-spec-transport06-evidence.md)
add five TRANSPORT-06 cases. An in-memory Inspector parser run checks bounded
text fragmentation, compression negotiation, and binary rejection; both cores
verify an isolated positive signature. The current integrated receivers remain
`UNSUPPORTED`.
The [registry record boundary scenarios](current-spec-reg01-evidence.md) add
five REG-01 cases and three controls for duplicate names, fragment collision,
the 128-entry lifetime limit, and exact KEM algorithm spelling. Both cores
verify selected proofs as primitives; the complete record verifier remains
`UNSUPPORTED`.
The [registry key-selection scenarios](current-spec-reg02-evidence.md) add
four REG-02 cases and three controls for ASCII KEM selection, proof and key
state, signature/KEM role separation, and immutable named key material. Both
cores match five isolated proof-signature expectations, but complete Registry
selection, authentication, and transition decisions remain `UNSUPPORTED`.
The [registry lifecycle scenarios](current-spec-reg03-evidence.md) add five
REG-03 cases and two controls for authenticated compare-and-swap, rejected
attempts with no mutation, terminal deactivation, and the version ceiling.
Both cores lack the complete mutation API. Their bounded local registry gates
also report mutation as `UNSUPPORTED` without changing their journals.
The [registry proof scenarios](current-spec-reg04-evidence.md) add five
REG-04 cases and four controls for historical KEM endorsement, registry
domain binding, controller transfer, signer-role separation, and KEM key
length. Both cores match six isolated signature expectations, but none of
the complete Registry proof and authorization cases is supported.
The [Registry observation scenarios](current-spec-reg05-evidence.md) add six
REG-05 cases and three controls for snapshot freshness, block consistency,
finality, source readiness, and revocation after selection. Both cores match
the bounded local gate sequences, but the complete dispatch decision remains
`UNSUPPORTED`.
The [eip155 deployment scenarios](current-spec-reg06-evidence.md) add five
REG-06 cases, each with a runtime and deployment-review binding. Synthetic
controls check code, ABI, finalized read consistency, and claim bytes and
block bounds. Both core runtime adapters lack the complete binding operation;
no deployed contract evidence exists, so deployment review remains `NOT_RUN`.
The [reserved Solana scenarios](current-spec-reg07-evidence.md) add two
REG-07 runtime cases for the exact `id.unknown-kind` error and refusal to
admit a Solana record as conformant. Both complete operations are
`UNSUPPORTED`; separate core DID syntax primitives accept the reserved kind,
which cannot establish resolver behavior.
The [web Registry scenarios](current-spec-reg08-evidence.md) add four
REG-08 runtime bindings for current origin reads, redirects, stale caches,
and missing authority. Both cores lack the complete web authority operation.
REG-08-N04 remains unbound because the web-origin response media type has no
normative acceptance rule in the pinned chapter; that specification decision
is recorded for the later review.
The [DID document projection scenarios](current-spec-resolve01-evidence.md)
add four RESOLVE-01 runtime bindings for exact projection, fabricated
relationships, missing document identity, and a key coordinate mismatch.
Both core primitive adapters lack the complete projection verification
operation; independent structural controls do not establish full conformance.
The [fresh DID resolution scenarios](current-spec-resolve02-evidence.md)
add six RESOLVE-02 runtime bindings for one configured web lookup and five
fail-closed conditions. Both cores lack the complete resolver operation;
the synthetic observation does not certify live Registry trust or proofs.
The [resolution metadata scenarios](current-spec-resolve03-evidence.md) add
four RESOLVE-03 runtime bindings for authoritative state projection, stale
cached success, an alias, and the wrong content type. Created and deactivated
records resolve for inspection while their protected-operation gate denies
authorization. Both core adapters lack the complete metadata operation.
The [exact key dereference scenarios](current-spec-resolve04-evidence.md)
add six RESOLVE-04 runtime bindings for canonical full key URLs, unknown and
revoked keys, service fragments, and relationship mismatch. Both core
adapters lack the complete fresh dereference operation.
The [HTTP resolution scenarios](current-spec-resolve05-evidence.md) add five
RESOLVE-05 runtime bindings for the versioned HTTP envelope, media type,
redirect, response size, and cache boundary. Nine RFC 9457-style problem
fixtures check exact local fields, while public problem-type URI publication
and an independent consumer remain unverified. Both core adapters lack the
complete HTTP resolution operation.
The [registry value governance scenarios](current-spec-table01-evidence.md)
add four TABLE-01 runtime and four document-review bindings for stable
registered meanings, obsolete-value reuse, silent incompatible changes, and
private wire values. Both core adapters lack the complete admission operation;
actual registration review remains `NOT_RUN` without an accepted proposal.
The [signature algorithm identifier scenarios](current-spec-table02-evidence.md)
add three TABLE-02 runtime bindings for the exact SAGE-local secp256k1 name,
the obsolete `es256k` name, and an inferred JOSE `ES256K` alias. Synthetic
dispatch controls check key roles, digests, and support policy. Both core
adapters lack the complete algorithm-selection operation.
The [registry key encoding scenarios](current-spec-table03-evidence.md) add
five TABLE-03 runtime bindings for record/JWK agreement, compressed and short
coordinates, and X25519 KEM role and length. Synthetic controls check exact
encoding and roles; both core adapters lack the complete key-encoding
operation.

The [domain separation label scenarios](current-spec-table04-evidence.md) add
four TABLE-04 runtime bindings for exact domain bytes, an obsolete label, an
omitted line feed, and a wrong HKDF role. Synthetic controls cover the other
registered delimiters and roles; both core adapters lack the complete
domain-registry operation.
The [registry kind selection scenarios](current-spec-table05-evidence.md) add
three TABLE-05 runtime bindings for configured eip155 selection, reserved
Solana refusal, and an unregistered kind. Synthetic controls cover optional
web policy and locator/descriptor shape. Both core adapters lack the complete
kind-selection operation.
The [transport header projection scenarios](current-spec-table06-evidence.md)
add three TABLE-06 runtime bindings for matching required and optional
headers, a body mismatch, and unsigned-header routing. Synthetic controls
check covered components and parameter equality; both core adapters lack the
complete header-binding operation.
The [diagnostic disclosure scenarios](current-spec-table07-evidence.md) add
three TABLE-07 runtime bindings for a generic public authentication failure,
a sensitive local diagnostic, and a reason-dependent public response. The
registered codes are pinned by independent controls; both core adapters lack
the complete diagnostic-boundary operation.

The five EXEC-01 cases now have partial deployment-review fixtures describing
the trusted Client assets, all six protected effect paths, the mandatory hook,
and the separate server verifier/dispatcher. An independent vector audit checks
that each negative changes one capability boundary. The bounded
`inspect_exec01_boundary.py` CLI detects missing or unsafe declarations in a
local description. It does not inspect the host, its actual credentials, or
its runtime process isolation. These cases remain `NOT_RUN` for implementation
conformance until a deployment review and runtime bypass-denial observations
are captured against a named subject. A core primitive result cannot establish
this host boundary.

The [EXEC-02 commitment observations](current-spec-exec02-evidence.md) provide
four partial runtime fixtures for exact original-request
framing and policy-descriptor commitment. The two mutation pairs check that a
changed captured byte or policy artifact changes the computed digest. These
primitives do not prove capture before expansion, policy authorization,
retirement ordering, or a downstream Agent's independent authorization.

The [EXEC-03 intent observations](current-spec-exec03-evidence.md) have six
partial runtime fixtures for a signed closed intent,
a changed argument, an independently signed unknown field, the generic JSON
size limit, an invalid nonce, and executor identity mismatch. The size probe
does not cover an actual oversized intent envelope, and the executor identity
probe does not cover outer HTTP identity binding.

The [durable dispatch observations](current-spec-exec04-dispatch-evidence.md)
cover four EXEC-04/05 cases with partial runtime fixtures for an inert core
dispatch sink. They distinguish one exact-argument commit, a changed approved
manifest, expiry before dispatch, and a crash/reopen that leaves the same call
`UNKNOWN` without a second dispatch. Parallel replicas, actual tool effects,
and the full guard order are outside these fixtures.

The [replay observations](current-spec-exec05-replay-evidence.md) add four
EXEC-05/CST-01 runtime fixtures exercising a separately signed
changed nonce, repeated exact envelopes, a changed proof, and UNKNOWN after
reopen. They bind only the local durable gate and an inert effect sink.

The [execution result observations](current-spec-exec-results-evidence.md)
add nine EXEC-06/07/08 cases with partial runtime fixtures for manifest
artifact bytes, signed result identity and intent binding, result expiry,
invalid proof, and MCP structured/text agreement. Loaded-instance integrity,
durable result consumption, and mandatory interception remain unobserved.

Three EXEC-09 document-review fixtures distinguish an approved-intent claim
from unsupported semantic-safety and whole-host-integrity claims. The bounded
claim classifier checks declarations only; it has not reviewed deployed
product wording or independent attestation evidence.

The [signed result lifecycle observations](current-spec-exec-result-state-evidence.md)
add three CST-01 cases with partial runtime fixtures for signed pending and
terminal snapshots, a rejection that races with an already committed
dispatch, and an expired terminal retrieval. They observe executor storage
and signature validity, not final Client output consumption.

The [Client result-consumption observations](current-spec-exec-client-evidence.md)
add four EXEC-07/CST-01 partial runtime cases for duplicate and delayed
results, conflicting terminal replies, polling frequency, and expiry. Both
cores match the bounded local Client and durable-journal fixtures. Model
decision and deployed transport boundaries remain unobserved.

The [three dispatch denial observations](current-spec-exec-denial-evidence.md)
add EXEC-04/CST-02 runtime fixtures checking that a locally denied
policy, unavailable active signing key, or prior retirement prevents an inert
dispatch. They do not establish resolver outage handling across replicas or
an atomic retirement race with a live external effect.

The [two missing-ledger observations](current-spec-exec-lost-ledger-evidence.md)
model EXEC-05/CST-02 loss of the local durable ledger after
one committed inert handoff. Reopening without the ledger must fail and
cannot recreate history or dispatch again. The trusted epoch-recovery
procedure remains outside this observation.

The [two pending-state observations](current-spec-exec-pending-evidence.md)
distinguish a signed `UNKNOWN` terminal outcome
from ordinary Client `pending`, and check the signed MCP pending projection.
Recovered server UNKNOWN issuance and the HTTP pending mapping still require
separate boundary evidence.

The [three signed hop observations](current-spec-hop-evidence.md) exercise
the Go and Rust core boundaries with an authenticated A-to-B intent, a fresh
B-to-C intent, and separate parent and B-side policy decisions. The authorized
fixture sends once; either missing B authorization or missing parent admission
prevents journal creation and transport handoff. These are partial runtime
observations. Host routing, protected persistence of parent admission, and
the exact source of an upstream UNKNOWN outcome remain unobserved.

The [two policy admission observations](current-spec-policy-admission-evidence.md)
show that a valid signature and matching policy digest do not override an
independent local policy denial, and that an incoming self-approved digest
cannot replace the pinned local mapping. Both cores reject the bounded signed
intents. Host ownership of the policy store and all downstream effect paths
still require separate review.

The [local key-rotation replay observation](current-spec-key-rotation-evidence.md)
records one inert dispatch before the signing key becomes inactive, then
refuses an exact replay from the reopened ledger. The ledger reports `UNKNOWN`
and the second attempt creates no additional handoff. Distributed rotation
authority and external effects remain outside this local boundary.

The 95 cases added after the historical snapshot comprise 71 MCP cases and
24 later corrections. The older 71-case MCP runtime overlay is useful bounded
evidence, but it was captured against an earlier spec revision; this inventory
does not automatically promote it. The eight later Registry cases have only
one partial exact-byte PoP observation and seven unrun cases. All 16 later
MSG-01 through MSG-03 cases now have partial runtime bindings. None has
complete receiving, state, and effect evidence.

Complete support requires a version-matched evidence binding and an
independent verdict for every case and mandatory subscenario, including
document and deployment review where the case demands it. Each bound result
must retain the spec revision, implementation revision, exact fixture and
observation, and applicable effects. Any absent binding remains `NOT_RUN` or
`UNSUPPORTED`; an observed mismatch is `FAIL`. Implementation-specific tests
may be added separately but cannot substitute for missing normative cases.
The current `sage-spec` standards-clause audit also records an unresolved
HTTP algorithm conflict; Inspector cannot assign a conforming expected
verdict for that boundary before the normative decision is made.
