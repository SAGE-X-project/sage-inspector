# Session inspection for SAGE 0.10.0

현재는 [유닛 중심 검증과 안전한 런타임 테스트](unit-test-verification.md)를 적용한다. 아래 실측은 과거 증거이며, 공격 재현 기능이 될 수 있는 경합·호스트 우회 프로그램은 현재 작업에서 실행하지 않는다.

Inspector preparation is complete: 55 independent record/key cases, 37 state
scenarios containing 248 steps, strict scenario execution, rule/hash manifests,
core record projections and a combined evidence command. This is not a claim that
the current cores implement 0.10.0 or that concurrent execution has been observed.

## Evidence and current results

| Core | PASS | FAIL | UNSUPPORTED | Stateful scenarios |
|---|---:|---:|---:|---|
| Go c7709b7486e0da94336edc0931fddd87f6a45343 | 11 | 26 | 18 | 37 NOT_RUN |
| Rust 206bbbb5a66667ae2feb3b0e9991ed1ca4622bb2 | 11 | 26 | 18 | 37 NOT_RUN |

Reports are in [evidence/session](evidence/session), with source and tooling hashes
in [provenance.json](evidence/session/provenance.json). Both overall results are
FAIL. All eleven PASS results are rejection observations. Positive controls fail,
so these negative observations do not isolate nonce, length, sequence, reflection,
AAD or transcript defenses. Never promote them into a rule-level security PASS.

Both existing public record APIs use historical HKDF labels with a session-ID
salt and an extra Extract, random nonces, and `be64(seq) || callerAAD`. They do not
accept th. The adapters pass the actual seed, sid, role, record and callerAAD to
those APIs; they do not implement the new key schedule/AAD/nonce validation to
make the old cores pass. The th field is retained for the normative expectation,
but cannot be supplied to these legacy APIs. Thus this is an explicitly limited
record API projection, not a complete session/envelope gate. Direct normative
key extraction has no corresponding public API and remains UNSUPPORTED.

Both core send APIs accept callerAAD4034 and a plaintext that produces an
8MiB+1 record in these projections. These are concrete missing-bound observations.
They are not a claim about protection elsewhere in an application stack.

## Independent calculations

[generate_session_vectors.py](../scripts/generate_session_vectors.py) reads the
public HPKE schedule-0 seed and transcript, then uses Python cryptography
HKDFExpand/ChaCha20Poly1305 without either SAGE core. The seed is the PRK: no
Extract. Directions c2s/s2c and sequences 0,1,255,256,511,512,767,768,999 cover
all four generations and transitions. Record tests cover tag/nonce/sequence/AAD
mutation, a cryptographically valid noncanonical nonce, reflection, different th,
seq1000/UINT64_MAX, minimum length, callerAAD4033/4034 on send and receive, empty
plaintext, and the send-side 8MiB record boundary.

[check_session_vectors.js](../scripts/check_session_vectors.js) independently
computes the single-block RFC5869 Expand with Node HMAC, seals/opens with Node
ChaCha20Poly1305, checks every expected result, and verifies the fixture manifest.
It also audits state expectations and record tags against a separate executable
model. The model is an expectation audit, never a subject adapter. It does not
prove real scheduling, trusted clocks, key erasure, or authoritative registry reads.
The HPKE known-answer inputs remain linked to the separately audited HPKE bundle.
All keys and private seed material are public test data.

Primitive operations:

- `sage.session.key`: seed_hex, th_hex, sid, direction, seq -> key_hex/generation.
- `sage.session.record.open`: seed_hex, th_hex, sid, direction, record_hex,
  caller_aad_hex -> plaintext_hex. Each case creates a fresh receiver opposite
  the specified sender direction; this operation makes no stateful replay claim.
- `sage.session.record.seal`: the same context with plaintext `{byte,length}`
  and caller_aad_hex -> record_sha256/record_bytes for the initial sequence zero.
  The bounded recipe permits the 8MiB sender boundary without exceeding the
  4MiB IPC limit. Expansion only constructs test input, never a verification result.

The recipe has byte 0..255 and length 0..8388573. Malformed/missing/null controls,
invalid hex or invalid trusted key lengths are adapter errors, not peer REJECT.
The accepted callerAAD IPC bound is 4034 so the out-of-profile boundary reaches
the core. AAD here is an isolated crypto input; full JCS envelope production and
HTTP authentication belong to the wire/HTTP inspection bundle. Receiver-side
8MiB streaming/transport resource enforcement still requires a suitable bounded
large-input binding; these send-side observations do not certify that behavior.

## Stateful binding contract

The existing schema2 runner executes each fixture in one persistent process,
without giving it expected outputs, effect counters or future steps. The bundle
accepts a real state adapter optionally; absence remains NOT_RUN. An adapter that
cannot provide a required control/instrumentation returns UNSUPPORTED. It must
not substitute this document's model for the core or invent effect counters.

`control.session.create` injects already authenticated HPKE state: the explicit
seed/th/transcript/sid, pinned signing/KEM bytes and algorithms, local role,
ESTABLISHED or RESPONSE_SENT, creation/idle time zero, and provisional deadline300.
This is an isolated session boundary, not another HPKE authentication test. The
fixture signing-key bytes are explicit synthetic registry controls for this
boundary; they do not attest that the archived HPKE transcript was signed with
these particular keys. The core must retain these bindings. The maximum policy
is absolute3600s, idle600s, 1000 records per direction, rekey256, no discretionary
close on isolated invalid records. A stricter production policy is allowed by the
spec, but must be disabled through an explicit test configuration for boundary
positive cases; otherwise return UNSUPPORTED instead of a misleading FAIL.

`control.clock.set` changes only injected monotonic protocol time. `subject.call`
uses these actions:

| Action | Required subject behavior and observation |
|---|---|
| receive | Feed record_hex/caller_aad_hex and envelope_projection at the authenticated session gate. signature_verified is a controlled upstream verifier result, never peer-supplied trust. Validate sender_role and the exact pinned tuple. Report canonical verdicts and cumulative accepted/dispatch counts. |
| send | Invoke the actual sender, record the allocated sequence. transport_failure injects failure after storing encrypted bytes and before emission: the harness action completes, but emitted remains unchanged. |
| retransmit | Retrieve the stored ciphertext for seq and compare bytes; changed_plaintext requests an illegal replacement. No allocation/re-encryption is allowed. |
| registry | At the actual resolver seam, make the named selected init/resp/KEM key revoked, selected material expired/unavailable/changed, or add an unrelated update. Refresh through the subject gate immediately. No real chain writes. |
| close / restart | Close actual state; restart the subject instance within the persistent adapter, without restoring session secrets or resetting into an active session. |
| inspect | Read state, next_send, sorted received sequences, last_activity, keys_available. The latter means logical key availability only, not a physical-memory erasure proof. |

`invalid` is a descriptive mutation label, not a verdict supplied to the core.
Envelope identity mutations are explicit in envelope_projection; bad tags are
actual modified wire bytes. The active-alternative-kid fixture requires the test
resolver to register that alternate key as active under the same DID so that only
the pinned-key gate rejects it. signature_verified=false must be injected at the
real upstream-verification seam; a binding cannot silently skip the failing gate.
These tests do not replace end-to-end envelope signature tests.

`subject.parallel` runs `parallel-send` count workers or `parallel-receive`
copies of the same authenticated record. All workers must enter a real shared
subject concurrently, with a barrier before the atomic commit attempt. Do not
place a barrier while holding the exclusive core lock. Aggregate only after all
workers complete. Send output sorts the actually returned sequences; receive
output sorts actual per-call verdicts (ACCEPT before REJECT) with counts. This
canonical multiset removes nondeterministic winner identity while preserving
multiplicity. Serial execution or fabricated aggregate counters is not evidence.
An optional commit_monotonic advances the injected clock after preliminary checks
but before atomic acceptance, specifically testing the provisional deadline recheck.

Every action is followed by inspection. Effects are cumulative accepted, emitted,
allocated, dispatch, confirmations and closed. Application rejection of a valid
first record still authenticates/reserves it and confirms the session, with zero
dispatch. Invalid tag/tuple/signature must not reserve a sequence or confirm.
Concurrency scenarios require exactly one acceptance of 16 copies and unique
allocations; at-most-once authentication is distinct from business exactly-once.

The fixtures also cover reordering 999 then0, replay, invalid high sequence then
valid same sequence, directional independence, transport gaps, cap exhaustion,
idle/absolute equality boundaries, invalid-input idle preservation, both local
roles, close/restart, each selected key's revocation, and provisional confirmation
without resetting absolute lifetime. Since every valid seq is 0..999, eviction
below a 1024-slot window is unreachable in one valid session. No fabricated seq1024
acceptance is used to claim a valid window-eviction test.

## Execution and limitations

```sh
go build -o /tmp/sage-conformance ./cmd/sage-conformance
go build -o /tmp/sage-scenario ./cmd/sage-scenario
node scripts/check_session_vectors.js
python3 scripts/test_session_inspection.py
python3 scripts/inspect_session.py --runner /tmp/sage-conformance \
  --adapter /absolute/core-adapter --subject sage-go --revision ACTUAL_REVISION \
  --output-dir /new/evidence-directory
```

Add both `--scenario-runner /tmp/sage-scenario --state-adapter /absolute/state-adapter`
when the real binding exists. Reports verify membership, hashes, identities,
expectations, effects, statuses and process exit. Existing output directories are
not overwritten. Exit0 means this bundle passed,1 FAIL,2 configuration/execution
error,3 INCOMPLETE. No result is a full-protocol certificate.

Core state bindings, real concurrency instrumentation, registry authority,
physical secret destruction and cross-core session interoperability remain explicit
follow-up work after the cores implement 0.10.0. This follows the agreed Inspector
first approach. The 386 baseline planned cases are not automatically marked PASS.
Retaining the seed permits deriving all generations; fixed rekeying is not a
forward-secure ratchet or a cure for a compromised signing endpoint.
