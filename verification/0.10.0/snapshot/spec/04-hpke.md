# 4. HPKE handshake profile

Status: normative design for SAGE `0.10.0`. This corrects the historical
handshake in `pkg/agent/hpke/`; `vectors/hpke.json` describes the old
schedule and is not a 0.10.0 conformance vector. Charter requirements:
[R-12, R-21 to R-23, R-26, R-30, R-35, R-36](../charter.md).

## 1. Suite and prerequisites

**HPKE-01 (R-12, R-21, R-23).** This version has exactly one suite:
HPKE Base mode, DHKEM(X25519, HKDF-SHA256) KEM `0x0020`, HKDF-SHA256
KDF `0x0001`, and ChaCha20-Poly1305 AEAD `0x0003`. Its SAGE name is
`hpke-base+x25519+hkdf-sha256`; combiner is `e2e-x25519-hkdf-v1`.
Only the HPKE exporter is used; session records use chapter 05.
Both peers MUST authenticate the transport envelopes using current proven
signing keys and resolve the responder's active X25519 key before
establishment. HPKE Base itself is not sender authentication.

All binary JSON fields below use canonical unpadded base64url. Context and
nonce are taken from the authenticated initiation envelope (chapter 08).
The context is a fresh UUIDv4 and MUST NOT be reused. `kemKid` is the exact
responder DID key URL selected before initiation.

## 2. Initiation and domain binding

**HPKE-02 (R-21, R-26, R-28).** The initiation payload is a closed JSON
object with exactly `v`, `task`, `ctx`, `initDid`, `respDid`, `initKid`,
`respKid`, `kemKid`, `suite`, `combiner`, `nonce`, `enc`, `ephC`.
`v` is `0.10.0`, task is `hpke/init@0.10.0`, both ephemeral fields
are 32 bytes, and all DID/key references MUST match the authenticated
participants and selected records. `respKid` selects the expected signing
key used for completion. This handshake does not use the optional generic `task_id`; the task
string is inside its signed payload only.

Before producing enc, form object B from those fields excluding `task`,
`enc`, `ephC`. Define:

```
info = UTF8("sage-hpke-info|0.10.0\n") || JCS(B)
exportCtx = UTF8("sage-hpke-export|0.10.0\n") || SHA256(info)
```

The initiator MUST create a fresh independent HPKE ephemeral encapsulation
and an independent X25519 ephemeral pair C. HPKE SetupBaseS to kemKid with
info yields enc and `exporterHPKE = Export(exportCtx, 32)`. The responder
recomputes B/info/exportCtx and obtains the same exporter via SetupBaseR.
No peer-supplied derivation string is trusted. Unknown suite, combiner or
version is rejected without downgrade negotiation.

## 3. Response transcript and combiner

**HPKE-03 (R-21 to R-23, R-26).** The responder generates fresh X25519
pair S and a fresh session handle `kid` (UUIDv4, not a registry key URL).
Transcript T is the complete initiation object plus `ephS` and `kid`;
there are no overwritten fields. `th = SHA256(JCS(T))`. Define:

```
ssE2E = X25519(privateC, publicS) = X25519(privateS, publicC)
prk = HKDF-Extract(salt=th, IKM=exporterHPKE || ssE2E)
seed = HKDF-Expand(prk, UTF8("sage-hpke-combiner|0.10.0") || th, 32)
ackKey = HKDF-Expand(seed, UTF8("sage-hpke-ack|0.10.0") || th, 32)
ackTag = HMAC-SHA256(ackKey, th)
```

All HKDF calls use SHA-256 and RFC 5869 argument meanings. Both HPKE KEM
and direct X25519 operations MUST reject all-zero shared results. Neither
component alone is used as a session key. The historical HMAC counter
expansion is removed; there is a single session schedule in chapter 05.

## 4. Completion message

**HPKE-04 (R-18, R-21, R-26).** The completion payload contains exactly
`v`, `task`, `transcript`, `ackTagB64`, `sigB64`. v is `0.10.0`, task is
`hpke/complete@0.10.0`, transcript is T and ackTagB64 decodes to 32 bytes.
The responder signs
`UTF8("sage-hpke-complete|0.10.0\n") || JCS(payload without sigB64)`
with respKid, encoding sigB64 as unpadded base64url. The outer signed
response additionally binds the initiation request under chapter 08.

The initiator MUST match every echoed initiation field byte-for-byte after
canonical encoding, check selected current keys, verify both response
signatures, compute ssE2E/seed and constant-time compare ackTag before
creating a session. It MUST NOT use a transcript supplied for another
pending request. Invalid completion destroys pending ephemeral state and
creates no session. Timeout requires a new context and fresh ephemeral keys.

## 5. State, lifetime and key confirmation

**HPKE-05 (R-21, R-22, R-26, R-36).** States are NEW → INIT_SENT
(initiator) or RESPONSE_SENT (responder) → ESTABLISHED → CLOSED.
For the initiator, INIT_SENT starts when initiation is emitted; for the
responder, RESPONSE_SENT starts when its completion response is emitted.
A pending state expires at 300 monotonic seconds after that transition or
at the initiation envelope's expires, whichever is first. RESPONSE_SENT is
also bounded by the completion envelope's expires. Check these absolute UTC
expiries with no late-expiry grace; equality is expired. A retransmission or
clock rollback MUST NOT extend the deadline. Trusted UTC and monotonic time
are required. The initiator reaches ESTABLISHED only after valid completion.

The responder's RESPONSE_SENT state has exactly one exception to chapter 08's
established-session requirement: it may receive initiator-role records for
its pinned tuple before the pending deadline. It MUST first verify envelope
schema, tuple, freshness, current bound keys, all required signatures and AEAD,
then atomically check/reserve the transport id/nonce and session sequence and
transition to ESTABLISHED. At that atomic boundary recheck the pending deadline
and that the state has not closed. No partial replay insert or state transition
may survive a failed authentication check. A concurrent record which finds
ESTABLISHED follows the normal established receive path; the transition occurs
only once. An exact concurrent duplicate is accepted at most once. The first
accepted sequence need not be zero: any unseen sequence below 1000 satisfying
chapter 05 is eligible, so loss/reordering of earlier records does not deadlock
confirmation.

The first accepted cryptographic record confirms key possession, even if its
application intent subsequently fails schema or authorization checks. Such
failure has zero protected effects and does not roll back the cryptographic
replay reservation or confirmation. The execution ledger is a separate later
gate under EXEC-04; its rejection is not a cryptographic acceptance failure.
An invalid signature/tag/tuple leaves provisional state unchanged, except that
timeout, failed bound-key validation or local resource closure closes it.
Before confirmation the responder MUST NOT send application data or execute
a protected operation. Afterwards it may send the specified signed/encrypted
application rejection. This supplies initiator key confirmation without a
second dedicated handshake round trip. Retransmitted initiation is rejected
by the normal nonce guard; it MUST NOT replace an existing session.

Every operation rechecks participant/key status under chapter 06. Changed,
revoked or unavailable authentication/KEM bindings close the session and
require a new handshake. Ephemeral private keys and exporter/ack material
MUST be erased once no longer needed; established state retains only the
session material required by chapter 05. Restart discards sessions; there
is no 0-RTT, session resumption, suite fallback or implicit shared-secret path.

## 6. Bounds and security review

**HPKE-06 (R-30, R-35, R-36).** Handshake payloads MUST be at most 16 KiB;
DID/key lengths follow chapter 06. Fixed binary fields and closed schemas
are checked before resolution or DH. A local admission/rate check MAY run
before authentication but MUST NOT assert peer identity. No interoperable
cookie exchange is defined in 0.10.0; cookie metadata MUST NOT change the
transcript or permit unsigned initiation. Failure is generic authentication
failure, with secrets excluded from logs.

The composition uses [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)
HPKE and [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) HKDF.
Transcript binding and the two-component combiner are SAGE design, not a
security theorem supplied by either RFC. Forward secrecy depends on fresh
independent ephemeral contributions and erasure. Formal authentication,
unknown-key-share, compromise and interleaving analysis plus independent
schedule vectors remain required verification work, not open wire choices.

Verified RFC 9180 errata 7937 (KEM suite identifier), 7121 (serialized X25519 private-vector clamping) and 7934 (distinct meanings of info arguments) apply when implementing HPKE-01/02. The verified Auth-mode claim correction 7790 is not a proof for this Base-mode composition. See the standards review.
