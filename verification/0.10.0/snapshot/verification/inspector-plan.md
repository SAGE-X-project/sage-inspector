# sage-inspector conformance plan

Target specification: **0.10.0**. Implementation owner:
`/Users/0xtopaz/work/github/sage-x-project/sage-inspector`.
This is a test contract, not executable tests or passed results. The current
inspector is reference evidence only; no code changes are made in this delivery.

## 1. Evidence model

[traceability.json](traceability.json) is the machine-readable requirement → rule
→ case mapping. Each case includes an input/scenario, preconditions, expected
outcome, mode and `planned_not_executed` status. A future case may expand into
several concrete independent vectors. Do not generate expected values using only
the implementation being tested, or count the old vector version as new evidence.

A future inspector report contains protocol/profile version, case ID, subject
repository/revision, runner/environment version, immutable input digest, expected
and actual verdict, state/effect counters, and evidence locations. Report PASS,
FAIL, UNSUPPORTED, NOT_RUN separately. Absence, skipped tests and wire-only checks
cannot certify host isolation or full Execution Guard.

## 2. Required test harness capabilities (future implementation)

Use synthetic test identities and isolated disposable effects, never production
keys or external live state. An executor fixture records dispatch count and exact
arguments, supports crash before/after reservation/commit, controls clocks and
registry snapshots, and coordinates concurrent replicas. Verify errors as well as
success: a generic remote failure must not leak local detailed authentication causes.

For all closed schemas expand mutation cases across every field: missing, null,
wrong type, duplicate, unknown member, lower/upper size boundary and one byte beyond;
for every authenticated field mutate independently. Exercise malformed UTF-8,
base64/JWK/scalars, canonical JSON number and Unicode corners. At every specified
expiry/rotation boundary test just below, exactly at, just above and concurrent arrival.

Network tests must distinguish signature verification from authorisation, response
binding and execution ledger acceptance. Test HTTP/WS where specified, direct local
MCP Execution Guard separately, and nested gates once per logical call. A valid
signature on an unsafe model proposal is a negative control, not a crypto failure.

## 3. Integration families referenced by charter

| Family | Main rule groups | Required evidence |
|---|---|---|
| IG-01 | EXEC-02, EXEC-03 | Trusted capture and authorised original/derived linkage |
| IG-02 | EXEC-03, EXEC-04 | Mutated intent rejected before dispatch |
| IG-03 | EXEC-01, EXEC-04, EXEC-08 | Missing/skipped/timed-out verifier always blocks |
| IG-04 | EXEC-06 | Baseline and check/load race protection |
| IG-05 | EXEC-04, EXEC-05 | Concurrent replay and durable crash-state handling |
| IG-06 | EXEC-07 | Exact result binding and pre-consumption verification |
| IG-07 | EXEC-01, EXEC-02, EXEC-08 | Isolated keys/gate and no unrestricted signing oracle |
| IG-08 | EXEC-08 | Each pinned host adapter intercepts all protected paths |
| IG-09 | EXEC-09 | Claim review excludes semantic/whole-host proof |

## 4. Case catalogue

The JSON contains one positive/review case and individual negative cases for each
semicolon-separated variant below. Values and expected verdicts are determined by
the referenced normative group. Cases are planned, not run. Pure document review
cases report nonconformance rather than sending meaningless network fixtures.

| Rule group | Requirements | Positive/review input | Negative/fault variants |
|---|---|---|---|
| OVERVIEW-01 | R-1, R-28, R-32 | Grammar and semantic bounds applied together | grammar used to override rejection rule |
| OVERVIEW-02 | R-31, R-32 | Version-specific dependency conformance claim | historical vectors advertised new conformance |
| OVERVIEW-03 | R-34 | Exact0.10.0 version throughout message/profile | missing version; mismatch across layers; automatic minor fallback |
| OVERVIEW-04 | R-32, R-33 | Text owns every protocol decision | Go implementation used to fill silent normative gap |
| CRYPTO-01 | R-8, R-19, R-29 | Supported exact Ed25519 suite and valid public key | RSA name; unknown suite; curve/algorithm mismatch; legacy es256k |
| CRYPTO-02 | R-19, R-29 | Independent valid signature for each supported suite | truncated signature; DER instead of raw; invalid curve point; noncanonical scalar; mixed-torsion Ed25519 point |
| CRYPTO-03 | R-19 | Low-S ECDSA signature with in-range r and s | high-S; r=0; s=0; out-of-range recovery byte |
| CRYPTO-04 | R-8, R-15, R-29 | Exact active DID key URL and correct domain | bare DID; wrong fragment; signature copied between domains |
| CRYPTO-05 | R-19, R-22 | Isolated signing service and independent ephemeral secrets | untrusted key access; repeated ephemeral key; retained erased-secret claim |
| JCS-01 | R-28, R-30 | UTF-8 JSON with unique members and finite numbers | duplicate key; BOM; lone surrogate; NaN; negative zero; negative underflow |
| JCS-02 | R-28 | Boundary-safe nonnegative protocol integer | fraction; negative timestamp; integer above safe range; wrong JSON type |
| JCS-03 | R-20, R-28 | Equivalent member orders yield exactly equal JCS bytes | array order mutation; Unicode normalisation; non-JCS number rendering |
| JCS-04 | R-20, R-28 | Only exact owning signature member omitted | remove nested proof metadata; remove all proof objects; alter authenticated alg |
| MSG-01 | R-19, R-20, R-34 | sig1 with required exact parameters and sha-256 digest | second signature label; duplicate parameter; unknown parameter; bad digest encoding |
| MSG-02 | R-15, R-16, R-20, R-34 | Exact method target authority body digest DID and version coverage | wrong target; forwarded-header spoof; unsigned body; missing version; unknown version |
| MSG-03 | R-18, R-20 | Response verified against stored original signed request | different request Signature; absent request context; wrong response peer; unsigned success |
| MSG-04 | R-20, R-30, R-35, R-36 | Bounded well-framed request and zero effects until verification | duplicate header; contradictory framing; 16MiB+1 body; 32KiB+1 fields; resolver timeout |
| MSG-05 | R-17 | Fresh unique nonce and atomic durable acceptance | expiry boundary; future created; nonce reused after key rotation; concurrent duplicate; lost state before360s |
| MSG-06 | R-35 | Generic authentication failure and signed authenticated application failure | detailed auth oracle; unsigned failure interpreted as success; plaintext fallback |
| HPKE-01 | R-12, R-21, R-23 | Fixed Base suite and active participant signing/KEM bindings | unsupported suite; missing sender signature; revoked KEM key |
| HPKE-02 | R-21, R-26, R-28 | Independent encapsulation and ephemeral key with exact B/info | changed DID; changed context; copied nonce; changed responder signing key |
| HPKE-03 | R-21, R-22, R-23, R-26 | Independent known-answer transcript/combiner calculation | zero DH secret; wrong transcript; swapped ephemeral; single-component secret |
| HPKE-04 | R-18, R-21, R-26 | Exact echoed transcript and valid ack plus both signatures | changed kid; bad ack; response from another pending request; bad completion signature |
| HPKE-05 | R-21, R-22, R-26, R-36 | Provisional responder waits for first valid initiator record | app effect before confirmation; pending timeout; retransmit replaces session; resume after restart |
| HPKE-06 | R-30, R-35, R-36 | 16KiB maximum handshake with cheap checks before DH | 16KiB+1; invalid fixed binary length; unsigned cookie bypass; secret in error log |
| SESSION-01 | R-26, R-27 | SID derived from exact handshake transcript and fixed roles | legacy direct secret; wrong transcript; swapped roles |
| SESSION-02 | R-25, R-27 | Generations at seq255/256 and seq999, lifetime below cap | seq1000; one-hour expiry; ten-minute idle; altered rekey interval |
| SESSION-03 | R-24, R-26, R-30 | Known-answer record with exact nonce direction and caller AAD | nonce mismatch; wrong direction; changed AAD; 4097-byte AAD; short/oversized record |
| SESSION-04 | R-24, R-27 | Concurrent sends allocate distinct sequence/key nonce pairs | reuse allocated seq after failed send; legacy separate MAC; new plaintext with old nonce |
| SESSION-05 | R-17, R-24 | Unseen authenticated reordered sequence accepted once | concurrent same seq; bad tag advances window; duplicate seq; out-of-window value |
| SESSION-06 | R-9, R-22, R-26 | Fresh handshake after closed state | revoked key; unreachable current state; expired key; restored reset counter; plaintext fallback |
| ID-01 | R-1, R-2, R-30 | Canonical DID/key URL inside grammar and length bounds | alias; percent escape; mixed case disallowed component; overlong DID; absent key fragment |
| ID-02 | R-2 | Same authoritative registry namespace gives same identity | different registry same agent local ID; chain alias; string normalisation collision |
| ID-03 | R-8, R-9, R-15, R-19 | One named active accepted key for exact sender | unknown key; revoked key; expired key; mismatched alg; unrelated registered signer |
| ID-04 | R-3, R-10, R-11 | Lifecycle invocation permitted by registry contract | unauthorised controller; rotation changes DID; key name reuse |
| CARD-01 | R-4, R-28, R-30 | Closed bounded card tied to current registry services | unknown field; wrong endpoint; unknown key; overlong card; schema mismatch |
| CARD-02 | R-8, R-19, R-28, R-29 | SAGE custom proof with all proof metadata authenticated | fake W3C suite; altered proof method; wrong domain; malformed signature |
| CARD-03 | R-4, R-8, R-9, R-36 | Fresh card for current record version and signer | expired unchanged card; wrong recordVersion; inactive Agent; stale service endpoint |
| TRANSPORT-01 | R-15, R-28, R-29, R-30, R-34 | Closed envelope with canonical fields | unknown member; invalid UUID; bad base64 padding; metadata over limit |
| TRANSPORT-02 | R-15, R-16, R-19, R-28 | Whole-request signature over exact payload/metadata | change recipient; mutate tool payload; strip metadata; wrong sender kid |
| TRANSPORT-03 | R-18, R-28 | Terminal response bound to stored exact signed request | wrong request hash; plaintext response to encrypted request; wrong response session role; second terminal success; missing error on false; unsolicited response |
| TRANSPORT-04 | R-17, R-30, R-35, R-36 | Atomic outer acceptance after every required verification | valid outer invalid inner; concurrent duplicate; session decryption fail; same id new nonce |
| TRANSPORT-05 | R-15, R-16, R-18, R-34 | HTTP and body signatures accepted once with equal fields | mismatched nonce/time/keyid; missing signature; unsigned header projection authority |
| TRANSPORT-06 | R-15, R-16, R-17, R-18, R-30 | One authenticated UTF-8 envelope per WS message | compressed frame; binary frame; oversized fragmented message; direct unsigned local bypass |
| REG-01 | R-4, R-6, R-28, R-30 | Complete closed record obeying types and bounds | duplicate key name; duplicate service id; fragment collision; over128 lifetime key tombstones |
| REG-02 | R-7, R-8, R-12 | Deterministic accepted key selection and immutable key identity | unproven selected key; revoked key used to authenticate a message; changed key material under same name |
| REG-03 | R-3, R-5, R-7, R-10, R-11 | Authorised atomic compare-and-swap lifecycle transition | stale expected version; concurrent mutation; inactive write; unauthorised operator |
| REG-04 | R-5, R-6, R-12, R-29 | Signing PoP bound to identity/key and KEM endorsement validated against historical signer even if now revoked; historical signer never authenticates new messages | PoP copied to another registry; changed controller; X25519 claimed signing proof; invalid key |
| REG-05 | R-9, R-13 | One authoritative snapshot at fresh dispatch gate | mixed blocks; latest-only unfinalised RPC; withheld head; revoked observed key; observation older5s |
| REG-06 | R-2, R-3, R-5, R-11, R-13 | eip155 binding includes registry code/ABI/finality authority | unknown deployment; code hash change; missing ABI; inconsistent state read |
| REG-07 | R-2, R-3 | Solana kind recognised as reserved and unsupported | Solana record accepted as conformant 0.10.0 |
| REG-08 | R-2, R-3, R-4, R-9, R-11 | Configured web authority with current validated read | redirect to another origin; stale cache; missing authority; unsupported media type |
| RESOLVE-01 | R-4, R-14, R-29 | Projection from one accepted record | fabricated verification relationship; missing id; inconsistent key coordinates |
| RESOLVE-02 | R-4, R-8, R-9, R-36 | One fresh authoritative lookup obeys fail-closed validation | unknown DID; malformed inactive record; stale observation; unauthenticated authority; positive cache reuse |
| RESOLVE-03 | R-4, R-9, R-14 | Resolution metadata records one authoritative state; created/deactivated records resolve for inspection but cannot authenticate | cached success treated as current; unknown alias; wrong content type |
| RESOLVE-04 | R-8, R-9 | Exact accepted key dereferenced from fresh DID document | missing fragment; unknown key; revoked key; service fragment used as key; wrong relationship |
| RESOLVE-05 | R-14, R-34, R-35 | HTTP resolution binding preserves document and errors | wrong media type; redirect authority change; oversized response; cached positive reuse |
| TABLE-01 | R-3, R-32, R-34 | Defined registered values preserve existing meanings | reuse retired code; silent incompatible extension; unknown private value accepted |
| TABLE-02 | R-19, R-29 | All suite identifiers match chapter01 | legacy es256k; JOSE mapping inferred from private Keccak name |
| TABLE-03 | R-29 | Key encodings match record/document binding | compressed secp when raw required; wrong coordinate length |
| TABLE-04 | R-19, R-28, R-34 | Labels equal exact bytes in each construction | old label with new version; omitted newline/NUL; wrong HKDF domain |
| TABLE-05 | R-2, R-3 | Supported registry kind plus valid deployment binding | reserved kind advertised supported; unknown kind accepted |
| TABLE-06 | R-15, R-34 | Mandatory version/DID and matching optional projections | header body mismatch; unsigned header used for routing |
| TABLE-07 | R-35 | Local diagnostics separated from remote generic failure | secret in diagnostic; reason-dependent authentication oracle |
| EXEC-01 | R-39, R-43, R-44, R-45 | Protected Client/executor with complete capability mediation | plugin reads signing key; replaces verifier; direct shell/network bypass; disabled hook |
| EXEC-02 | R-37, R-38, R-43, R-45 | Original captured before expansion and exact derived call authorised | original overwritten; unchecked model proposal signed; digest accepted as permission |
| EXEC-03 | R-37, R-38 | Closed versioned intent and correct domain signature | tool/recipient/arguments changed; unknown field; 1MiB+1; bad nonce; outer inner identity mismatch |
| EXEC-04 | R-38, R-39, R-41 | All gates succeed and exactly verified arguments dispatch once | missing verdict; unavailable resolver; manifest mismatch; last-moment mutation; expiry before dispatch |
| EXEC-05 | R-39, R-41 | Durable reservation survives parallel calls and crash | same call new nonce; replay after key rotation; lost ledger; UNKNOWN auto-retry; cancellation after commit misreported |
| EXEC-06 | R-40, R-43, R-45 | Protected complete baseline pins actual loaded code/schema | baseline self-update; symlink; uncovered dependency; file swapped after check; remote hash treated as attestation |
| EXEC-07 | R-42, R-45 | Exact signed result consumed once for pending intent | wrong result issuer; wrong intent digest; expired output; duplicate consumption; unsigned tool output injected |
| EXEC-08 | R-39, R-43, R-44 | Authenticated compulsory MCP execution wrapper | LLM skips verify tool; unrestricted sign tool; timeout fail-open; notification dispatch; direct protected-tool call; divergent structured/text result |
| EXEC-09 | R-45 | Claims explicitly scoped to approved intent and trusted boundary | valid signature advertised semantic safety; file hash advertised whole-host assurance |
| PROC-01 | R-32, R-33 | Rule groups map to requirements and planned cases | unmapped MUST rule; implementation declared normative |
| PROC-02 | R-31, R-32, R-33, R-34 | Old/new behaviour and version-pinned evidence distinguished | historical vector relabelled0.10.0; unexecuted test claimed pass |
| PROC-03 | R-32, R-33 | Existing docs updated and source repos unchanged | competing canonical specification; product/source code mutation |
| EVIDENCE-01 | R-13, R-31, R-33 | Published cost/latency and independent interoperability plan with versioned evidence | unmeasured latency advertised; two same implementation wrappers claimed independent proof |

## 5. Existing evidence and gaps

The six historical suites under `vectors/` contain 26 cases at
`1.0.0-draft.1`. Retain them unchanged. The current inspector and code paths are
linked by the [evidence graph](../analysis/graphs.md); historical reports are not
relabelled as current pass results. New domains, envelopes, timing, registry and
execution semantics require new fixtures and adapters in follow-up work.

## 6. Security analysis and measurements (not wire tests)

Model the HPKE transcript, both ephemeral contributions, signing/KEM key status,
key confirmation, interleaving, unknown-key-share and post-session compromise in
Tamarin or ProVerif (tool choice remains an implementation decision). The acceptance
claim must name assumptions, secrecy/agreement properties, counterexamples and
proof status; RFC composition alone is not proof. Model ledger crash/replay safety
separately from a transactional tool's business exactly-once guarantees.

Measure registration, authoritative resolution and revocation publication/observation
latencies separately, including chain finality and clock assumptions. Report operation
cost, payload size, throughput and percentile latency with repetitions, hardware,
network, fixture and source revision. Compare SAGE/no-SAGE demos under the same
policy and sandbox, and explicitly show validly authorised unsafe-content controls.
No measurements, proof or live conformance run were performed in this delivery.

## 7. Follow-up implementation order

Implement stable parsing and independently checked vectors, then core wire and
state tests, then HTTP/WS cross-core exchange, then host-specific Execution Guard
fault injection. Registration/lookup convenience services and demos consume the
same contracts. Do not start actual repository migration as a side effect of this
plan; follow the [separate migration design](../architecture/migration-plan.md).

## 8. Contract closure review — 2026-09-14

CST-01..05 are resolved at the document-contract level; see the
[closure and re-review](crypto-trust-closure.md). Inspector implementation may
proceed against this revised snapshot; that is not a passed implementation or
security certification. Independent composition and host-isolation evidence remain
release gates. No Inspector code has been started.

## 9. Added closure scenarios

The original 358 cases are retained. The following 28 explicit cases bring the
catalogue to **386 planned cases**; all remain `planned_not_executed`. These cases
supplement section 4 rather than changing historical case IDs. Exact scenarios and
expected outcomes are in [traceability.json](traceability.json).

| Case | Rule | Scenario | Required outcome |
|---|---|---|---|
| CST-01-01 | EXEC-05 | Duplicate versus intact absence/lost ledger | Existing call returns pending without redispatch; intact absence permits original execution once; lost ledger denies. |
| CST-01-02 | EXEC-07 | Pending then completion | Accept completed once for the tracked call; outer response binds the new invocation; no second response to the first invocation. |
| CST-01-03 | EXEC-07 | Delayed pending after terminal | Ignore the verified delayed pending; do not reopen the call or consume more output. |
| CST-01-04 | EXEC-07 | Conflicting terminal reply | Reject conflict; preserve first outcome. Identical terminal envelope is ignored. |
| CST-01-05 | EXEC-05 | UNKNOWN versus ordinary waiting | Live entry yields pending; recovered entry yields stored signed unknown once available and never auto-dispatches. |
| CST-01-06 | EXEC-05 | Changed inner proof on retry | Reject nonidentical envelope and leave the existing operation unchanged; client must retain original proof. |
| CST-01-07 | EXEC-08 | HTTP and MCP pending mapping | Empty output; MCP isError=true and matching canonical structured/text values; wire success=false,error=unavailable. An unsigned unavailable error authorizes nothing. |
| CST-01-08 | EXEC-05 | Expiry and polling frequency | First may return a snapshot; equality fails freshness without redispatch; trusted Client does not issue the too-fast poll. No new call ID bypass. |
| CST-01-09 | EXEC-07 | Rejection persistence race | Only a terminal no-dispatch ledger entry can publish rejected; an existing reservation cannot be overwritten. A recorded rejection cannot later execute. |
| CST-01-10 | EXEC-07 | Terminal result expires or key revoked | Fail retrieval without refreshing, re-signing, or executing. Retain historical outcome for protected reconciliation. |
| CST-02-01 | EXEC-02 | Policy descriptor canonical commitment | JCS descriptor bytes and domain-separated SHA-256 match the published commitment; array/file byte order is not normalized. |
| CST-02-02 | EXEC-02 | Policy artifact mutation | Pinned-artifact validation fails; no signing/dispatch under the old approved commitment. |
| CST-02-03 | EXEC-02 | Retirement versus dispatch | A single serialized gate orders them: retirement first yields zero dispatch; already committed effect is not described as rolled back. |
| CST-02-04 | EXEC-02 | Ledger-loss epoch recovery | Unsynchronized scope remains fail-closed; resume only after all affected old commitments are rejected and the new mapping is durable. |
| CST-02-05 | EXEC-02 | Peer self-provisions policy | Deny; incoming material cannot install a mapping. Reusing an old epoch for restored bytes is not valid administration. |
| CST-03-01 | SESSION-03 | AAD exact boundary | Complete AAD is4096 bytes and is within sender/receiver limits. |
| CST-03-02 | SESSION-03 | AAD one byte over | Complete AAD4097 is rejected by sender and receiver before AEAD; metadata allowance does not override it. |
| CST-04-01 | SESSION-01 | Wrong participant with valid crypto | Reject pinned tuple mismatch before acceptance; valid crypto is not sufficient. |
| CST-04-02 | SESSION-01 | Same DID alternative active key | Reject; switching keys requires a fresh handshake. |
| CST-04-03 | SESSION-01 | Recipient or role mismatch | Reject each mismatch; no replay/state acceptance or application effects. |
| CST-04-04 | SESSION-01 | Bound key revoked versus unrelated update | Revocation closes without substitution. Unrelated update alone leaves the pinned active tuple usable; new handshake selects current KEM. |
| CST-05-01 | HPKE-05 | First record before deadline | Atomically reserve transport nonce/id and seq and establish once, then separately evaluate tool authorization. |
| CST-05-02 | HPKE-05 | Exact pending deadline | Each equality closes/rejects; no grace or dispatch. |
| CST-05-03 | HPKE-05 | Forged first record | Do not reserve replay state or establish; remain provisional unless separate local closure applies. |
| CST-05-04 | HPKE-05 | Concurrent first records | Identical copy accepted once; distinct valid records may both be accepted but only one establishes and both obey separate execution authorization. |
| CST-05-05 | HPKE-05 | Policy-denied authenticated first record | Session is established and cryptographic replay state retained; zero protected tool effects; permitted encrypted rejection does not unconfirm. |
| CST-05-06 | HPKE-05 | First record after sequence loss | Confirm if otherwise valid and before deadline; do not require seq0 or reset counters. |
| CST-05-07 | SESSION-02 | Confirmation does not extend session age | Confirmation does not restart session absolute/idle lifetime; only specified accepted traffic resets idle. |
