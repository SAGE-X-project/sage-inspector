# 5. Session layer

Status: normative design for SAGE `0.10.0`. Historical evidence:
`pkg/agent/session/{session,manager,types}.go`, `vectors/session.json`.
These old vectors use different nonce/derivation rules. Requirements:
[R-17, R-22, R-24 to R-27, R-30](../charter.md).

## 1. Inputs and session identity

**SESSION-01 (R-26, R-27).** Inputs MUST be the 32-byte seed and 32-byte
transcript hash th from chapter 04, plus its fixed initiator/responder roles.
No default label, externally supplied secret or non-directional legacy key
path is supported. Session id is:

```
sid = base64url(SHA256(UTF8("sage-session|0.10.0") || th)[0:16])
```

This 22-character public identifier is distinct from the handshake's UUID
handle kid. Both are bound to one transcript; neither grants authority.

Each session MUST retain the authenticated tuple `(v, ctx, initDid, respDid,
initKid, respKid, kemKid, suite, combiner, kid, th, sid)` from chapter 04 and
its local role. Key URLs and the selected public-key bytes/algorithms are pinned.
For every record, including the provisional first record, the receiver MUST require:

| Sender role | Envelope did | Envelope recipient | Envelope kid | AEAD direction |
|---|---|---|---|---|
| initiator | T.initDid | T.respDid | T.initKid | c2s |
| responder | T.respDid | T.initDid | T.respKid | s2c |

The sender role MUST be opposite the local role. Version, session_id and
context_id MUST equal T.v, sid and T.ctx. The receiver MUST check the tuple
before accepting the record; a valid signature and AEAD tag cannot substitute
for these equality checks. Switching even to another active signing key of the
same DID requires a new handshake. Current status of both selected signing keys
and the selected KEM key MUST be checked under REG-05; revoked, expired,
unavailable or changed selected material closes the session, without substituting
another key. Adding an unrelated key or updating a service does not alone change
this pinned tuple or close an otherwise valid session. New handshakes apply the
current KEM-selection rule; established sessions retain their selected KEM key.

## 2. Directional key schedule and limits

**SESSION-02 (R-25, R-27).** Each direction has its own sequence counter,
starting at zero. The initiator sends c2s; responder sends s2c. For sequence
seq, generation is `g = floor(seq / 256)`. Derive the AEAD key as:

```
key = HKDF-Expand(seed, UTF8("sage-" || direction || "-key|0.10.0") || th || be64(g), 32)
```

HKDF-Expand is RFC 5869 SHA-256 with seed used directly as PRK. Rekey
interval 256 is fixed; disabling or negotiating it is not supported.
The historical defaults of 1000 records per direction, 1 hour absolute
session lifetime and 10 minutes idle lifetime become upper bounds.
Implementations MAY close earlier for local policy. A sender MUST close
before sending seq 1000; a receiver MUST reject seq >=1000. Expiry starts
at session key-state creation on each endpoint, using a monotonic local clock.
For the responder this includes provisional key-state creation; confirmation
MUST NOT restart the absolute or idle lifetime.
Idle time resets only on successfully authenticated accepted traffic or a
successfully emitted record, never unauthenticated input.

## 3. Record format and AAD

**SESSION-03 (R-24, R-26, R-30).** A record is:

```
be64(seq) || nonce[12] || ciphertext || tag[16]
nonce = zero[4] || be64(seq)
aad = UTF8("sage-record|0.10.0") || th || directionByte || be64(seq)
      || be32(length(callerAAD)) || callerAAD
```

AEAD is ChaCha20-Poly1305 (32-byte key, 16-byte tag); directionByte is 0
for c2s and 1 for s2c. Received nonce MUST equal its specified value.
Random record nonces are no longer permitted. Distinct direction keys and
fresh handshake seeds prevent nonce reuse across directions/sessions.
A record is at least 36 bytes and at most 8 MiB; plaintext therefore fits
within `8 MiB - 36`. CallerAAD is at most 4033 bytes. Under chapter 08 it
is JCS of the wire request/response excluding `payload` (or `data`) and
`signature`, with the sender filling all other members before encryption.
The complete AAD has 63 fixed bytes (18-byte domain, 32-byte th, one direction
byte, eight sequence bytes and four length bytes) plus callerAAD. Both sender
and receiver MUST enforce complete AAD <=4096 bytes and callerAAD <=4033 bytes
before AEAD work. Thus callerAAD4033/complete4096 is within bounds, while
callerAAD4034/complete4097 is rejected. Satisfying the separate metadata cap is
insufficient. No caller-specific alternate AAD interpretation is supported on
this wire.

**SESSION-04 (R-24, R-27).** Concurrent sends MUST atomically allocate a
unique sequence. Once allocated, a sequence MUST NOT be reused even after
transport failure; retransmission reuses identical stored ciphertext only
and is still subject to receiver replay rejection. Key/nonce reuse to
encode a different plaintext is forbidden. The legacy separate MAC path
is not part of 0.10.0: AEAD authenticates the complete record and AAD, and
chapter 08 authenticates the envelope. APIs cannot claim conformance by
using a MAC over caller-selected unrelated bytes.

## 4. Replay and ordering

**SESSION-05 (R-17, R-24).** Each receive direction maintains a 1024-slot
sliding bitmap and highest authenticated sequence. Duplicate sequences
and values below the window MUST be rejected. Authentication and replay
acceptance MUST form one atomic operation: failed AEAD never moves the
window, and concurrent copies have at most one acceptance. The fixed
message cap still applies even if a bitmap could accept a larger value.
Missing records do not authorize guessing plaintext or resetting counters.

Out-of-order unseen records inside the window are permitted; their seq
provides authenticated order, not an instruction to execute operations in
arrival order. Applications needing ordered effects MUST enforce their
own dependencies before execution. Cryptographic reordering tolerance is
not automatic exactly-once or sequential business semantics.

## 5. Closure and security considerations

**SESSION-06 (R-9, R-22, R-26).** Expiry, restart, participant/key revocation,
failed current registry validation or explicit local closure prevents
further acceptance and destroys keys. No restored state may reset counters;
0.10.0 deliberately has no persistence/resumption protocol. Invalid records
are rejected without advancing state; resource abuse may trigger closure.
Peers recover through a fresh authenticated handshake. An error MUST NOT
cause plaintext fallback or reuse of retired keys.

[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) defines the AEAD;
nonce uniqueness above is the SAGE profile's construction. The bounded
session reduces exposure but does not prove compromise recovery: generations
derive from one retained seed and do not form a forward-secure ratchet.
Independent derivation vectors, nonce allocation races, expiry/restart,
reflection and cross-generation tests remain inspector follow-up.
