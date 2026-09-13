# CST-01..05 closure and re-review

Date: **2026-09-14**. Version: **0.10.0, unpublished working-draft revision**.
Decision: **GO for sage-inspector implementation against this revised contract**.
This is document readiness, not implementation conformance or production approval.
All five findings are closed at the specification level; executable checks remain
planned. No Inspector or core source was changed and no implementation was started.

## Changes and cross-layer review

| Finding | Resolution | Re-review result |
|---|---|---|
| CST-01 | Added signed pending snapshot; each invocation ends once; later read reuses exact inner envelope with fresh outer identity; terminal envelope is immutable | Pending/terminal operation state is separate from transport completion; no replay redispatch or second response |
| CST-02 | Defined domain-separated commitment of JCS policy descriptor, artifacts, issuer and fresh epoch; protected mappings and serialized retirement | Exact bytes are reproducible; incoming digest grants no installation authority; epoch recovery retires all affected old authorizations |
| CST-03 | Both directions enforce complete AAD <=4096 and callerAAD <=4033 | Fixed prefix is63 bytes; the4033/4034 caller boundary now has an explicit answer |
| CST-04 | Stored session participant/key tuple and per-role equality table; no alternate signing key in an existing session | Another valid DID/key/tag cannot satisfy a mismatched tuple; unrelated registry updates are distinguished from bound-key changes |
| CST-05 | Explicit provisional receive exception, deadlines and atomic crypto acceptance, followed by separate execution authorization | First record can confirm without authorizing its tool; invalid records cannot confirm; concurrent confirmation occurs once |

The changes clarify the unpublished draft and add pending to its closed result enum.
Existing draft implementations must update explicitly; accepting the old three-state
result schema is not current conformance. The requested target remains 0.10.0. No
released version or historical vector was relabelled.

## Re-review scenarios

The review traced both ordinary and adversarial paths through the owning rules.
These are document-level conclusions, not runtime test results.

- **Pending then completed:** initial request returns pending and ends. A new
  invocation reads the same call; completed is accepted once. No second response
  is sent to the original HTTP/JSON-RPC invocation.
- **Replies arrive out of order:** terminal first, then an already outstanding
  pending reply: pending is ignored. Two different terminal envelopes conflict;
  identical terminal envelopes are ignored after first consumption.
- **Rejection/reservation race:** a signed rejected outcome requires a durable
  no-dispatch terminal entry. It cannot overwrite another invocation's reservation;
  later policy changes cannot cause that recorded rejection to execute.
- **Crash versus waiting:** running means pending; durable uncertain outcome means
  unknown. Unknown never triggers automatic re-execution or later conflicting
  terminal publication. Reconciliation is separate.
- **Transport retry:** exact outer frame is a replay. Fresh outer identity carrying
  the identical stored inner envelope is a status read. Re-signing the inner object
  is not identical; no new call ID is used to bypass an uncertain outcome. If the
  original never arrived and the durable ledger is intact, its original authorization
  may execute once. Resubmission is therefore not a strictly read-only query when
  absence is uncertain; lost-ledger state remains fail-closed.
- **Expiry/revocation:** every read checks current access and freshness. At intent
  expiry, new reads stop. A previously accepted invocation can report a fresh outcome
  after intent expiry; result time still must pass. Expired/revoked terminal envelopes
  are not refreshed or re-signed. Long-running outcomes outside the retrieval window
  require protected reconciliation; no cancellation or portable status API is implied.
- **Policy retirement:** dispatch and retiring its commitment serialize at the same
  gate. Already committed effects are not undone. A partially updated receiver cannot
  keep dispatching under a retired epoch. Whole affected scope must reject old
  commitments before lost-ledger recovery resumes.
- **Session substitution:** even deliberately valid signatures and AEAD from a
  participant do not permit a different DID, recipient, key, context or role. Adding
  an unrelated registry key does not alone terminate a pinned valid session.
- **Provisional confirmation:** first unseen seq3 is valid after earlier loss. A bad
  tag leaves state unchanged; a valid but policy-denied record confirms the session
  while causing zero tool effects. At a pending deadline equality is expired.
- **Concurrency:** the first successful cryptographic transaction reserves outer
  id/nonce and sequence and confirms once. A second distinct record may follow the
  established path; an exact duplicate cannot pass twice. Execution reservation is
  separate and still compulsory. Application rejection does not undo crypto replay.

These checks led to two additional clarifications within the five fixes: durable
rejection cannot race into a later execution, and provisional confirmation cannot
restart the session's absolute lifetime. No additional unresolved contract blocker
was identified in this bounded re-review.

## Policy commitment byte example

This is an informative document example, not an executable conformance vector or
an approved production policy. Its ASCII-only string/object members permit an exact
JCS example without implementing a general canonicalizer. The synthetic policy file
contains five bytes, `deny` followed by LF. The UUID is a fixed fixture value; real
administration generates a fresh unpredictable UUIDv4. A real policy descriptor
must include the evaluator and complete dependencies, not only this illustrative file.

Canonical P:

```json
{"artifacts":{"files":[{"path":"policy.txt","sha256":"a29d20c44b5b445eb9e43ffc1c136950317ceb9736c1c9464839ee7af3d68cea"}],"version":"0.10.0"},"engine":"example-deny/1","epoch":"00000000-0000-4000-8000-000000000001","issuer":"did:sage:web:agents.example.com:policy-example","version":"0.10.0"}
```

`SHA256(UTF8("sage-policy|0.10.0") || 0x00 || JCS(P))`:

```
e70a2dfb87b9a2760e540a2ca96e16d55ec1fb346cfeba7515ed40ca5ab08bdb
```

An independent implementation must reproduce these bytes/hash for this example;
changing the epoch or any artifact bytes changes the commitment. Semantically equal
rules with different bytes are not silently normalized. This illustrates commitment
encoding only, not approval of the example's incomplete deployment artifacts.

## Traceability and observed checks

The original 358 cases are retained, with **28 explicit closure cases** added:
**45 requirements /77 rule groups /386 planned cases**. All remain
`planned_not_executed`. The authored trace graph is now **2626 nodes /5189 edges**;
raw AST and historical source evidence are unchanged. See
[inspector plan](inspector-plan.md) and [traceability.json](traceability.json).

Local artifact checks cover JSON parsing, case/reference uniqueness, reciprocal
rule/case mapping, normative source-line references, graph endpoints/counts, links,
unchanged raw AST, and preservation of six historical vector files. The policy
example hash and the63-byte AAD arithmetic were recomputed in temporary scripts.
Those scripts are not delivered tools, crypto implementations or runtime tests.

## Readiness boundary

Inspector development can now include the revised pending/result lifecycle,
policy commitment, AAD boundary, session identity tuple and provisional-state
oracles. Start with version-pinned reporting and independently sourced fixtures;
then implement controlled state/concurrency tests and host adapters. Do not generate
all expected values through the same core being tested.

CST-A1 (independent custom-composition analysis), CST-A2 (host capability/isolation
observations) and CST-A3 (independent oracle evidence) remain open assurance work.
They are necessary evidence for security approval and relevant conformance claims,
not reasons to prohibit building the tools that collect that evidence.

The re-review was performed locally by the same assistant, using actual files and
cross-layer scenarios. It is not an external cryptographer audit, formal proof or
multi-model consensus. No external QA transmission was retried. There is no new
Ouroboros score or formal approval. The earlier [review](crypto-trust-review.md)
remains as historical findings; the [current gate JSON](crypto-trust-review.json)
records their document-level closure and preserves their original source evidence.
