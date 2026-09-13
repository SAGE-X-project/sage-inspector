# Agent and MCP security integration profile

Version: **0.10.0**. Normative profile of the [core specification](../spec/00-overview.md).
Status: design for independent implementation; no runtime conformance or security proof is claimed.
The uppercase requirements use BCP 14. `EXEC-*` identifiers are stable rule groups;
[charter](../charter.md) R-37 through R-45 provide their requirements.

## 1. Protection and trust boundary — EXEC-01

An Execution Guard implementation MUST protect the trusted Client's original-request
store, authorisation policy, signing keys, component reference manifests, verifier,
and final dispatch gate against writes and impersonation by ordinary plugins, skills,
MCP servers, model output and their child processes. Signing a request proves what
this trusted gate authorised; it does not prove that an LLM understood the user.

The attacker may replace a plugin, MCP implementation or skill after a clean enrolment,
alter requests and responses, bypass optional model tools, and attempt direct calls.
The trusted gate MUST mediate every protected effect, including subprocess, network,
file, retry, parallel and subagent paths; capabilities or credentials that permit a
direct bypass MUST NOT be available to untrusted components. A deployment that cannot
enforce this boundary MUST NOT claim the Execution Guard profile. Network-only
Verifier/Peer conformance does not imply Execution Guard conformance.

The server-side verifier and dispatcher are trusted independently of an untrusted tool
implementation. Merely placing the verifier inside the replaceable MCP process is
insufficient. A malicious tool with unrestricted host privileges can act without any
message; preventing those effects needs capability isolation, not another signature.

Compromise of these trusted parts, trusted-key use outside the gate, and pre-enrolment
substitution are excluded. The last is a follow-up research item without a promised
release number. A privileged gateway holding a principal's key is inside that
principal's trust boundary, never an untrusted transparent intermediary.

## 2. Capture, derivation and authorisation — EXEC-02

The Client MUST capture the user's submitted UTF-8 bytes before untrusted expansion,
assign an unpredictable request identifier, and retain the immutable original and its
SHA-256 commitment in its protected store. No Unicode or whitespace normalisation is
performed for this commitment. The capture boundary (typed prompt, API submission, or
trusted workflow input) MUST be disclosed in deployment documentation. Every capture is an ordered list of inputs (one item for a single prompt). The commitment input is `UTF8("sage-original|0.10.0") || 0x00 || be32(item_count)` followed by each item encoded as `be64(byte_length) || bytes`; original_digest is SHA-256 of this input. At most 1024 inputs and 1 MiB aggregate captured bytes are allowed. A changed or extended list receives a new request ID. This framing prevents single-input versus bundle ambiguity.

A model or tool MAY propose a derived call. The trusted Client MUST authorise the
exact recipient, tool name, arguments, component manifest and policy before signing.
The policy MUST resolve to executable allow/deny rules and MUST NOT consist solely
of an instruction to the LLM to call a security tool. Human confirmation is optional
under the Client's policy, and disabling confirmation MUST NOT disable verification.
Authorising a derived call records a decision; its signature is not an independent
proof of semantic equivalence to the original natural-language request.

The original digest is an audit commitment, not a secret and not authorisation by
itself. A receiver MUST trust the configured issuing principal and its authorisation
policy for the permitted operation; DID registration alone does not grant permission
to invoke tools. The original text need not be disclosed to that receiver.

### Policy commitment and revision

The approved policy descriptor P is a closed JCS object with exactly `version`
(`0.10.0`), `issuer` (canonical issuing DID), `epoch` (fresh canonical UUIDv4),
`engine` (1..128 ASCII bytes identifying the exact evaluator/version), and
`artifacts` (the `version`/`files` manifest defined in EXEC-06). P is at most 1 MiB
canonical UTF-8, depth 32 and 4096 aggregate object members. Policy artifacts MUST
contain at least one file. The smaller applicable
bound governs. Define, in lowercase hexadecimal:

```
policy_digest = SHA256(UTF8("sage-policy|0.10.0") || 0x00 || JCS(P))
```

Artifacts MUST cover the executable evaluator, rules and configuration that determine
allow/deny and their loadable dependencies. The engine identifier MUST map to that
pinned implementation; an identifier alone is not code-integrity evidence. Ordinary
runtime inputs (the current request, clock and validated registry observations) are
not fixed policy artifacts; the rules for interpreting them are. A universal policy
language is not required. Semantically similar policies with different artifact bytes
are different commitments; implementations MUST NOT normalize policy file bytes.

Trusted administration provisions P and an immutable mapping from `(issuer,
policy_digest)` to the approved policy/epoch and permitted receiver operations.
The receiver MUST recompute the commitment from its provisioned descriptor and check
the applicable mapping; it need not execute the issuer's policy language. A descriptor
supplied by a call cannot provision or approve itself. The issuer gate MUST actually
evaluate the pinned policy before signing. Unknown, retired or issuer-mismatched
commitments are denied even when the request has a valid signature.

Any effective policy/evaluator change requires a fresh epoch and administrative
approval. An epoch MUST NOT be reused, including when restoring old policy bytes.
Retiring a commitment atomically prevents new dispatch under it and invalidates its
not-yet-dispatched reservations at each affected receiver. Dispatch and retirement
MUST serialize at the same protected gate; retirement cannot undo committed effects.
During rollout an unupdated receiver MUST be denied access to protected dispatch until
its approved mapping is synchronized. Lost-ledger recovery by a policy epoch change
requires retiring every outstanding pre-recovery commitment across the affected
execution scope, durably installing the new mapping, and refusing old commitments
before resuming. If that cannot be established, the receiver MUST remain fail-closed.
Neither a process restart nor generating an unused epoch string alone is recovery.

## 3. Execution intent encoding — EXEC-03

An intent is the following closed JSON object. Every field is REQUIRED; unknown,
duplicate or mistyped fields are rejected. JSON and key/signature validation follow
[02](../spec/02-jcs.md) and [01](../spec/01-crypto.md). Integers are exactly represented
non-negative JSON safe integers. Digests are exactly 64 lowercase hexadecimal digits.
UUIDs are lowercase canonical UUIDv4 strings; identifiers are never reused.

| Field | Type / bound | Meaning |
|---|---|---|
| `version` | string, exact `0.10.0` | Protocol version |
| `profile` | string, exact `sage-execution-guard` | Domain of the authorisation |
| `request_id` | UUIDv4, 36 ASCII bytes | Original Client request |
| `call_id` | UUIDv4, 36 ASCII bytes | Single proposed execution |
| `parent_call_id` | UUIDv4 or JSON null | Causal parent; null for root |
| `original_digest` | digest | SHA-256 of the domain-separated capture encoding in section 2 |
| `issuer` | canonical DID, <=256 UTF-8 bytes | Trusted authorising Agent |
| `recipient` | canonical DID, <=256 UTF-8 bytes | Executing Agent/MCP boundary |
| `tool` | string, 1..128 ASCII bytes | Exact registered tool name, `[A-Za-z0-9_.-]+` |
| `arguments` | JSON object | Fully resolved arguments; no unsigned defaults |
| `policy_digest` | digest | Commitment to the approved descriptor P in EXEC-02 |
| `manifest_digest` | digest | Approved executor component manifest |
| `created` | integer | Unix seconds at issuance |
| `expires` | integer | Exclusive expiry, greater than created, at most created+300 |
| `nonce` | base64url-raw, 22 chars | 16 random bytes |
| `keyid` | string, <=289 UTF-8 bytes | Issuer's active signing verification method |
| `alg` | string, <=64 ASCII bytes | Algorithm from chapter 01 |

The envelope is exactly `{"intent": <object>, "proof": <base64url-raw>}`.
Proof is the signature over `UTF8("sage-execution-intent|0.10.0") || 0x00 || JCS(intent)`.
Proof length after decoding is fixed by the selected algorithm; other encodings fail.
The complete envelope MUST NOT exceed 1 MiB UTF-8, depth 32, or 4096 object members
in aggregate. Strings under `arguments` are bounded by this total and the registered
tool's tighter schema. Unknown tools, unknown argument members, unresolved defaults,
unsupported values or a tool without an enforceable closed schema MUST be rejected.
The limit includes keys, proof and JSON punctuation and is checked before crypto.

For HTTP carriage this object MUST be the decoded payload of chapter 08's authenticated envelope, which is carried under chapter 03. For a non-HTTP
MCP connection the direct intent binding in section 8 is still required in full (this claims Execution Guard, not chapter 08 WireTransport); absence of HTTP headers never removes
intent verification. Transport authentication and execution authorisation are
separate checks. Outer sender/recipient MUST equal intent issuer/recipient. Outer transport nonce/time fields are separately validated; they do not replace or extend the inner intent lifetime. The intent replay ledger uses a distinct namespace from the outer transport ledger. A relay changing outer transport does not gain permission to
change the intent or proof.

## 4. Enforcement state machine — EXEC-04

```text
RECEIVED -> BOUNDED -> AUTHENTICATED -> AUTHORISED -> RESERVED -> EXECUTING
     \          \             \             \          \           |
      ------------------------ REJECTED       UNKNOWN <-------------+
                                                        \          |
                                                          COMPLETED
```

The receiver MUST, in order:

1. Bound and parse the message, reject unsupported version/profile, invalid schema,
   algorithm and tool, and invalid time. A clock within 30s of UTC is a prerequisite;
   otherwise deny. Require `created <= now+30` and `now < expires` with no late-expiry
   grace, and require the stated 300s maximum lifetime.
2. Resolve issuer/key under chapter 10, verify proof and active signing relationship,
   require the DID part of `keyid` to equal `issuer`, and compare `recipient` to this executor. This step MUST NOT execute tool code.
3. Match issuer, policy digest, manifest digest, tool and final arguments to the
   receiver's protected authorisation policy and approved component state. Do not
   accept a digest or allow decision simply because the incoming request supplies it.
4. Look up `(issuer, call_id)` in the durable execution ledger. If already present,
   follow EXEC-05's exact-envelope snapshot branch and MUST NOT reach step 5 again.
   For an absent call, atomically reserve `(issuer, call_id)` in the ledger and
   `(issuer, recipient, nonce)` in the freshness ledger. A different intent reusing either
   identity is rejected. The original proof bytes and their digest are retained.
5. Check that authorisation, active identity and measured execution capability remain
   valid, and dispatch the exact verified arguments to the pinned component instance.
   Any mutation or expiry before dispatch aborts the reservation without execution.

All rejection paths before dispatch MUST produce zero protected effects. Retrying
transport verification MUST NOT create a second execution. Reservations are exclusive
across concurrent threads, processes and replicas: a deployment unable to share or
partition the ledger consistently MUST deny overlapping dispatches.

Expiry and revocation apply at the dispatch boundary; they cannot undo an external
effect already committed. Long-running tools may be cancelled best-effort, but the
profile does not claim rollback of committed effects. This distinction is reported.

## 5. Replay, crashes and cancellation — EXEC-05

The ledger stores the exact canonical intent envelope, its digest, issuer, dispatch
state and terminal result until at least `expires+30` and while execution is unresolved.
An identical duplicate means identical JCS of the entire intent envelope, including
proof. Re-signing, changing inner nonce/time or arguments is not identical and MUST
NOT replace a reserved call. A sender MUST retain the original envelope for retries.

A verified identical duplicate never reserves or dispatches again. While state is
RESERVED or EXECUTING, the receiver returns a signed `pending` snapshot under EXEC-07.
After a durable terminal outcome it returns the same stored terminal result envelope,
while valid. A pending snapshot MAY also be the first reply after reservation when
execution has not yet finished. `pending` means the operation is reserved/running;
it is not success, rejection or crash uncertainty. `unknown` is reserved for durable
uncertainty after a crash or loss of outcome knowledge, never ordinary waiting.

Each transport invocation receives at most one response: either pending or a terminal
snapshot. An eventual completion MUST NOT be pushed as a second response to that
invocation. A trusted Client MAY retrieve a later snapshot by resubmitting the exact
original intent envelope before its expiry. Each retrieval uses a fresh outer wire
id/nonce (and fresh session sequence, if used), or a new direct MCP JSON-RPC request
ID. It is a read of the existing call, not a new execution. Exact outer-message replays
remain rejected by the transport guard. Polls MUST be at least one second apart per
call and MUST stop at terminal status or intent expiry; a transport error alone does
not authorize redispatch. An unverified/lost response may be reconciled through this
same identity-preserving resubmission; it MUST NOT create a new call ID.
If the original never reached the receiver and no entry exists in an intact durable
ledger, resubmission follows the normal initial authorization path and may execute
once. The original signed intent remains an execution authorization until expiry;
this binding has no read-only query flag. A Client needing a strictly read-only
reconciliation without that possibility MUST use protected administration instead.
Lost-ledger state MUST NOT be treated as an intact empty ledger.

Freshness, authentication and current access policy checks apply to every retrieval.
If these no longer pass, fail the retrieval without overwriting an existing execution
or manufacturing a `rejected` outcome for it. After intent expiry no new retrieval is
accepted, even with a cached result. An already accepted invocation may return a
freshly signed outcome after intent expiry; result freshness is independently checked.
Expired/unavailable terminal results and outcomes unresolved beyond this retrieval
window require protected administrative reconciliation, which is not a new portable
query or cancellation protocol in 0.10.0. Expiry of a read does not prove cancellation.

If a crash occurs after reservation and before completion is durably recorded, mark
the call UNKNOWN on recovery and MUST NOT auto-dispatch it. The owner must reconcile
the external outcome; exactly-once effects are not guaranteed across a crash without
a transactional tool. Loss of the ledger or of trusted time requires denial of new
execution until state recovery or a protected policy/key epoch change invalidates all
outstanding authorisations. Merely restarting the process MUST NOT clear replay state.

Cancellation invalidates a not-yet-dispatched local capability. A remote cancellation
is a separately authorised tool call; it does not retroactively erase the original.
A new desired action receives a new call ID and policy evaluation. Retrying with a
new ID solely to bypass UNKNOWN is not permitted by the trusted Client policy.
Parent IDs express causality; they grant no delegated authority or wider permissions.

## 6. Component manifest and load binding — EXEC-06

The protected baseline is a JCS object with exactly `version` (`0.10.0`) and `files`
(an array). Each file is exactly `path` (relative UTF-8 path <=1024 bytes) and `sha256`
(lowercase digest). Paths use `/`, have no empty, `.` or `..` component, no backslash,
NUL, symbolic link or duplicate, and are sorted by UTF-8 byte order. Files are regular
files; hashes cover exact bytes. At most 4096 files and 1 MiB canonical manifest bytes
are permitted. `manifest_digest` is SHA-256 of these canonical bytes.

The manifest MUST cover executable code, transitive loadable dependencies, scripts,
skills, tool descriptions/schema and configuration affecting dispatch. Dynamic loading
of uncovered material MUST be denied. A receiver checks an incoming manifest digest
against its own approved baseline; a caller cannot approve new code by naming its hash.

Hash verification MUST precede loading and bind to the same immutable artifact instance
that executes. Hashing a path and reopening it later is insufficient. Isolation,
read-only images, pinned handles or equivalent enforcement are implementation choices.
The gate and baseline update authority MUST be outside the plugin's write capabilities.
Baseline replacement requires an authenticated administrative decision, records old
and new digests, invalidates pending calls against the old baseline, and never silently
approves a changed file. The setup period is not a repeated automatic re-enrolment.

A peer-supplied manifest hash is not evidence of its machine's runtime integrity.
Remote attestation, hardware roots of trust and whole-host integrity proofs are not
defined by 0.10.0. Claimed deployment protection relies on its trusted local boundary.

## 7. Protected results — EXEC-07

The executor returns exactly `{"result": <object>, "proof": <base64url-raw>}`.
The result object has required fields `version`, `request_id`, `call_id`, `issuer`,
`recipient`, `created`, `expires`, `keyid`, `alg` with the definitions above (issuer
is now the executor, recipient the Client), plus `intent_digest` (SHA-256 of JCS of
the entire intent envelope), `status` (one of `pending`, `completed`, `rejected`,
`unknown`), and `output` (a JSON object, empty unless completed). No other fields are allowed.
The 1 MiB/depth32/member4096 bounds apply. Proof signs
`UTF8("sage-tool-result|0.10.0") || 0x00 || JCS(result)`.

Before exposing output to the model, user or downstream tool, the Client MUST verify
the active signer, recipient, time, request/call IDs and exact intent digest against
its tracked call. The result keyid DID MUST equal result issuer and the expected
executor. Each result MUST correspond to an outstanding transport invocation; an
unsolicited response is rejected. A valid signature from an unrelated
registered Agent is insufficient. Results are data, not policy, new skills or grants.
Following an instruction in a result always requires a new policy-governed call.

The Client tracks one operation across its transport invocations. Verified pending
snapshots leave it unresolved, provide no consumable tool output, and may differ in
creation/expiry/signature bytes. The first verified terminal result is consumed once.
Thereafter an identical terminal envelope is ignored; a different terminal envelope
is a conflict and MUST NOT replace the accepted outcome. A delayed pending snapshot
from a previously outstanding invocation is ignored after terminal acceptance and
MUST NOT reopen the call. A pending snapshot cannot authorize another operation.

At the executor the first terminal outcome and its signed result envelope MUST be
persisted atomically before publication and reused without re-signing or refreshing
its times. `rejected` is permitted only when the ledger guarantees no dispatch occurred.
Before publishing `rejected` for a previously absent call, the receiver MUST
atomically create its terminal ledger entry and reserve the intent nonce, using
the same uniqueness rules as EXEC-04. If another invocation already reserved or
executed it, a rejecting invocation MUST NOT overwrite that state or publish a
conflicting rejection; it returns a retrieval/authentication failure instead.
Thus a previously rejected call cannot later execute after a policy change.
A recorded `unknown` is terminal for this protocol: later reconciliation does not
publish a conflicting completed result for the same call. If the signer becomes
unusable or the result expires, a retrieval fails; it does not mint a replacement
terminal envelope. The ledger's state, not a poller's arrival order, determines the
snapshot. Local resource failure before durable terminal publication cannot claim
completed. A crash-recovery UNKNOWN record may acquire its one stored signed result
when the trusted signer becomes available, without invoking the tool again.

If no trustworthy response can be produced, local transport failure is reported as
unverified; it MUST NOT be accepted as an authenticated remote verdict or successful
execution. Failure details are visible only to the trusted local operator, not through
an authentication oracle. Protected error responses obey core error constraints.

## 8. MCP integration contract — EXEC-08

This profile defines a proposed SAGE MCP binding, not a change to MCP itself.
The receiver exposes `sage_secure_call` with input schema exactly one property,
`envelope`, containing the intent envelope above (`additionalProperties: false`).
Its result contains the protected result envelope above as `structuredContent` and
one text block containing its canonical JSON; both representations MUST agree or
the Client rejects. No extra content blocks, model instructions or unsigned result annotations are consumed. `isError` MUST be false exactly when protected result.status is `completed`, and true otherwise. In chapter 08 carriage `success` is true exactly when result.status is `completed`; otherwise error is `unavailable` for `pending`, `operation_failed` for `unknown`, and `policy_denied` for `rejected`. The unavailable mapping carries an authenticated pending snapshot; by itself an error code is never evidence that polling or execution is authorized. Authentication failures that cannot safely return a protected result remain unverified transport failures. The negotiated MCP version MUST support structured tool results;
the baseline is MCP `2025-06-18`. Unsupported versions fail profile setup.

The ordinary target tool is identified by the signed `intent.tool`, not an unsigned
outer argument. `sage_secure_call` MUST NOT be a permitted inner tool (no recursive
security wrapping). Unsigned direct calls to a protected tool MUST be rejected at
the same executor boundary. A new JSON-RPC request ID does not change call identity.
Protected calls MUST NOT be accepted as notifications or unverified batch shortcuts.

Authorisation/signing is an internal trusted Client operation. An implementation MAY
host it in a protected security MCP service, but MUST authenticate its caller and
accept only a Client-issued protected authorisation capability bound to the exact
intent; it MUST NOT expose an unrestricted `sign(anything)` tool to the model/plugins.
The representation of an in-process capability is local, unexported, and not a new
portable wire credential in 0.10.0.

Model-visible verification tools are optional diagnostics, never the enforcement
mechanism. Hooks, SDK middleware and proxies may implement the gate; each adapter
MUST demonstrate complete interception and deny on no verdict, exception, disconnect
or timeout. If the host cannot enforce that, the adapter MUST declare unsupported
instead of advertising Execution Guard. The user may choose an unprotected mode,
but it MUST NOT silently downgrade a protected request or claim this profile.

## 9. Security rationale and verification — EXEC-09

An implementation MUST NOT advertise semantic safety, remote runtime attestation or whole-host compromise protection solely from conformance to this profile (R-45).

RFC 9421 supplies message-component authentication, not natural-language intent
validation; RFC 9530 binds body bytes only when its digest is authenticated.
RFC 9396 informs structured authorisation design, but the intent above is SAGE's
own format, not an OAuth token or an assertion of OAuth interoperability.
RFC 9334 distinguishes attestation evidence and appraisal: a bare file hash is not
a substitute for remote attestation. See [standards review](../verification/standards.md).

Required inspector families are `IG-*` in the [plan](../verification/inspector-plan.md):
wrong recipient/tool/argument, signing-oracle access, optional verification skip,
parallel/restart replay, manifest replacement, check/load race, result substitution,
and malformed/oversized encodings. No such implementation tests were run in this
documentation phase. A signature-valid but malicious model proposal remains subject
to Client authorisation policy; preventing all semantic prompt injection is not claimed.
