# 8. Transport envelope

Status: normative design for SAGE `0.10.0`. Historical Go evidence:
`pkg/agent/transport/wire.go`, `transport/http/{client,server}.go`.
The prior payload-only signature left routing metadata and WebSocket
responses unbound; this version signs the whole envelope. Requirements:
[R-15 to R-20, R-26, R-28 to R-30, R-34 to R-36](../charter.md).

## 1. Common schema

**TRANSPORT-01 (R-15, R-28 to R-30, R-34).** All envelopes are closed JSON
objects with the following required common members. Optional means omitted,
not null; unknown top-level members MUST be rejected. Text sizes are UTF-8
byte counts. Canonical UUIDv4 uses lowercase hex and hyphens, with RFC UUID
version/variant bits set. All binary strings use unpadded base64url with
canonical pad bits; padded or alternate encodings MUST be rejected.

| Member | Constraint |
|---|---|
| `version` | exactly `0.10.0` |
| `id` | fresh UUIDv4 identifying this message |
| `did`, `recipient` | sender and intended recipient DIDs; chapter 06 limits |
| `kid` | sender's full signing key URL; chapter 06 limits |
| `created`, `expires` | integer Unix seconds; freshness rule chapter 03 §4 |
| `nonce` | 16 random bytes encoded as 22 base64url characters |
| `encoding` | `plain` or `session` |
| `signature` | encoded chapter 01 signature, at most 87 characters |

Optional common fields are `context_id` (UUIDv4), `task_id` (UUIDv4),
`session_id` (22-character chapter 05 sid), `role` (exactly `initiator` or
`responder`) and `metadata`. Metadata has at most 32 entries with keys
matching `[a-z][a-z0-9_]{0,31}` and string values at most 1024 bytes each;
its complete JCS encoding is at most 4096 bytes. Metadata is authenticated
but grants no authority. `session` encoding requires the full participant/key,
version, session_id, context_id and role tuple checks of SESSION-01.
The session MUST be ESTABLISHED except for the responder's sole provisional
receive exception defined by HPKE-05; that exception does not skip tuple,
signature, AEAD, freshness or replay checks. `plain` MUST omit
session_id; if role is present it MUST match the handshake role.

## 2. Request body and signature

**TRANSPORT-02 (R-15, R-16, R-19, R-28).** A request additionally requires
`payload` (base64url bytes, decoded size at most 8 MiB). Its signature is:

```
Sign(kid, UTF8("sage-wire-request|0.10.0\n") || JCS(request without signature))
```

Every member, including sender, recipient, key reference, context, metadata,
version and payload, is covered. The signature algorithm comes from the
resolved key, never untrusted metadata. HTTP additionally binds method and
target under chapter 03. Logical tool name, resource and executable inputs
belong to the authenticated payload and the
[Agent–MCP profile](../profiles/agent-mcp-security.md), not to unsigned
transport hints. A session payload is the complete binary chapter 05 record;
a plain handshake payload is UTF-8 JCS of chapter 04's object.

## 3. Response and exact request binding

**TRANSPORT-03 (R-18, R-28).** A response uses the common schema and adds
`message_id` (request id), `request_hash` (32-byte SHA-256), `success`
(boolean), and `data` (base64url bytes, at most 8 MiB decoded). When false,
`error` is required and exactly one of `authentication_failed`,
`policy_denied`, `operation_failed`, `unavailable`; when true, error MUST
be absent. Empty data is encoded as the empty string. Response context_id
and task_id MUST equal their request values, including absence. Response
id and nonce are fresh, did equals request recipient, and recipient equals
request did. Define:

```
request_hash = base64url(SHA256(JCS(complete signed request envelope)))
response signature = Sign(kid,
    UTF8("sage-wire-response|0.10.0\n") || JCS(response without signature))
```

A verifier MUST retain its sent envelope, recompute request_hash and match
message_id before result use. Unsolicited responses and second acceptance
of a terminal response MUST be rejected. There is one terminal response
per request; progress and streaming application events require separately
authenticated requests and are not implicit additional responses. An Execution
Guard `pending` snapshot is the sole final response to its transport request,
while the underlying operation remains unresolved. Later status retrieval uses
a new authenticated transport request with the unchanged inner intent under
EXEC-05; no second response or automatic redispatch is implied.
A response to a session-encoded request MUST use session encoding with the same session_id and context_id and the opposite sender role. A plain request has a plain response, including handshake completion. Session closure MUST NOT cause a plaintext response fallback. Errors are not permission to downgrade or silently re-execute an operation.

## 4. Receive processing and replay

**TRANSPORT-04 (R-17, R-30, R-35, R-36).** JSON envelopes MUST fit 16 MiB
and JCS chapter limits. Receivers first check size/schema/canonical binary
encoding, recipient, version and timing; then resolve current keys, verify
the full signature and any HTTP binding; then decrypt session content and validate its AEAD. For session messages,
cryptographic acceptance atomically reserves id/nonce and session sequence,
including HPKE-05's provisional transition when applicable. For plain messages
cryptographic acceptance atomically reserves id/nonce. The execution profile
is validated afterwards, with its own durable execution reservation before
dispatch. Application rejection does not release cryptographic replay state;
concurrent copies never execute twice. The replay persistence/retention rules in chapter 03 §4
apply equally on HTTP, WebSocket and local MCP adapters. Message ids are
reserved for the same duration as their nonce using the same sender and
recipient scope. A different nonce does not make an already accepted id
fresh.

Failure produces no application side effect. Trusted callers receive an
explicit local verification failure; an untrusted caller gets only generic
authentication failure. Unsigned connection errors may signal failure but
MUST NOT be accepted as authenticated application results. Execution may
have committed before a response is lost; automatic retry of a new id
requires application-level reconciliation, not a claim of exactly-once
execution from transport replay protection.

## 5. HTTP binding

**TRANSPORT-05 (R-15, R-16, R-18, R-34).** HTTP uses chapter 03 on both
request and response, with TLS server authentication. X-SAGE-DID and
X-SAGE-Version are mandatory and MUST match the body. Optional
X-SAGE-Message-ID, X-SAGE-Context-ID and X-SAGE-Task-ID, if present, MUST
match their body counterparts; a missing counterpart is a mismatch.
Arbitrary X-SAGE-Meta-* projection is removed to avoid header-name collisions.
Routing and authorization MUST use verified body fields rather than optional
header projections. HTTP signature keyid, times and nonce MUST equal the
body values. Both signatures are required: the inner signature protects
transport-independent identity/context, the outer binds HTTP routing/status.
One acceptance transaction covers both, not two independent replay inserts.

## 6. WebSocket and local adapters

**TRANSPORT-06 (R-15 to R-18, R-30).** WebSocket uses one UTF-8 JSON
envelope per reassembled text message over authenticated TLS. Fragmentation
MAY occur, but the 16 MiB limit applies during reassembly; binary messages
and per-message compression MUST be rejected in this profile. The connection
does not authenticate later messages by itself: each envelope is verified.
Registered recipient identity and execution payload bind the logical target;
connection URL alone MUST NOT supply authorization. Local adapters claiming this chapter's WireTransport conformance use
the same envelope checks and explicit expected recipient, and MUST place
verification in an unavoidable trusted execution path. The direct local MCP binding in the Execution Guard profile is a distinct profile binding and does not claim this chapter's carriage conformance. No reliance on an
LLM choosing to call a verification tool constitutes conformance.

## 7. Migration and verification

New members, base64url, whole-envelope domains and response request hashes
are incompatible corrections. Legacy base64 payload-only messages MUST NOT
be silently accepted as 0.10.0. Existing header vectors test only historical
HTTP behavior. Envelope tampering, response substitution, transport replay,
header/body disagreement and concurrent dispatch need new inspector cases.
The profile is an application design using [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html)
and [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html); neither RFC
makes signed tool content semantically trustworthy.
