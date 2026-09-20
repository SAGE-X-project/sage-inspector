# Non-HTTP MCP authenticated setup proposal

Status: **proposed design, not an adopted 0.10.0 wire requirement**. This document
resolves the non-HTTP choices raised by the
[setup review](https://github.com/SAGE-X-project/sage-inspector/blob/3d2c2679e8dc6b70391e7c5a7d4e934445d023c2/docs/mcp-setup010.md).
It does not make existing cores conformant, update retained vectors, or replace the
uncommitted local 0.10.0 design. MUST/SHOULD below apply only if this proposal is
adopted. Protocol implementation, independent vectors and host enforcement remain
NOT_RUN. Publication of this proposal is not adoption or a protocol release.

The [basis](basis.json) records the local design hashes and reviewed core identities.
The proposed rule groups are local `MSET-01..08` IDs, not additions to the existing
386-case normative catalog until adoption. The [case plan](cases.json) and
[document checker](verify.py) check design traceability, not cryptographic execution.

## Scope and compatibility

This is a custom non-HTTP MCP transport binding for one initiator/client and one
responder/server. SAGE channel establishment precedes the MCP lifecycle. Both hosts
MUST select this binding through trusted deployment configuration, before parsing
traffic. There is no unprotected probe, fallback, new cipher, transcript field or
portable authorization token. Lack of support aborts setup without a protected call.

The binding supports exactly MCP `2025-06-18` in this draft. That is a binding
support decision, not a claim that the broader SAGE baseline permanently prohibits
later versions. MCP version, SAGE `0.10.0`, cryptographic session ID, JSON-RPC ID and
outer message ID are distinct. HTTP, stdio framing, SSE, multiple MCP connections
multiplexed over one SAGE session, and server-initiated calls are outside this binding.
A new SAGE session requires new MCP setup. Protected Guard ledgers survive separately.

[MCP lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)
defines initialize request/response followed by initialized notification and operation
under negotiated capabilities. This proposal adds stricter admission and authenticated
carriage, without changing those MCP message types. Custom transports and HTTP's
separate rules are described in
[MCP transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).
The transport acknowledgement below is not an MCP response to a notification.

## MSET-01 — Channel and ownership

The client MUST authenticate the SAGE handshake before sending initialize. The
server may accept that first encrypted initialize record through the existing
provisional responder receive rule: full peer/tuple, signature, freshness, replay and
AEAD checks precede channel confirmation. MCP readiness does not follow from channel
confirmation alone. No plaintext setup or plaintext error fallback is permitted.

A trusted local connection owner retains the exact session object, pinned identity
and key tuple, accepted MCP version, setup request, pending carrier and state. Model
or plugin inputs cannot assert readiness. Readiness is local, unexported state, never
a wire capability, and cannot transfer to another session, peer, role or connection.
Every message still requires current registry checks and normal session validation.
Handshake, registry, lifetime and replay protections are not weakened by this draft.

## MSET-02 — Message carriage and bounds

Existing signed session request/response envelopes carry the exact UTF-8 MCP JSON
bytes as encrypted plaintext. The usual outer signature, AEAD callerAAD, request_hash,
message_id and participant correlation remain mandatory. They are not replaced by
parsing inner JSON. Outer and inner request IDs are distinct UUIDv4 strings; an outer
ID collision with the inner ID is rejected. Inner notifications have no ID.

For this binding each decrypted control message is at most **16,348 bytes**, the
current core carriage ceiling, not the larger general session maximum. Wire messages
are at most **32,768 bytes**. Reject invalid UTF-8, duplicate JSON members, batches,
trailing JSON, wrong message shape and excess depth (>36) before changing MCP
admission state or causing application effects. An authenticated record may already
have consumed cryptographic sequence/replay state; rejecting its inner JSON MUST NOT
restore that state. An outer validation failure follows the underlying transport
acceptance rules instead of inventing a second replay policy.
Use the versioned MCP schema for initialize fields; optional descriptive fields are
not authority and MUST NOT be forwarded as model instructions. No automatic signing,
policy change, artifact installation or tool execution occurs during setup.

The trusted owner serializes state transitions and output commitment. Preparing an
immutable authenticated output reserves its sequence and invocation but enters a
local OUTPUT_PENDING barrier, not the advertised next state. The bounded local send
must report full success before that next state is published. A partial write,
uncertain completion, cancellation or send failure closes the connection. Send success
is only a local handoff guarantee, never proof of peer receipt or disk persistence.

While OUTPUT_PENDING, no inbound message or callback may dispatch, publish readiness
or reenter the owner. A receiver may defer at most one size-bounded frame until the
barrier clears; it then runs normal authentication and state checks. Overflow closes
the connection. A response arriving before the sender's send callback returns is
subject to the same barrier. Failed or closed output never activates deferred input.
No second output, sequence reuse or duplicate response is created by cleanup.

All control messages consume normal directional sequence and outer replay budgets.
At most one control request is outstanding. The client MUST retain its exact sent
outer envelope until its sole correlated response is authenticated or the connection
closes. Application validation failure never rolls back cryptographic acceptance.
Setup messages never enter the protected tools/call parser or Guard execution ledger.
The connection owner nevertheless retains one client JSON-RPC request-ID history
across initialize, tools/list and all later protected requests. Reserve a syntactically
valid ID of an authenticated request before routing it; repeated IDs close the
connection before dispatch. IDs are never released on response completion or failure.
Sender and receiver both enforce this rule. A newly created Guard endpoint cannot
reset it. The history is bounded to 1024 request attempts including setup; exhaustion
closes the connection, and any tighter record/session limit still applies. Notification
carriers consume outer replay/sequence budgets but have no inner request ID.

## MSET-03 — Initialize and negotiation

Client state CHANNEL_AUTHENTICATED permits exactly one initialize request. It uses a
fresh canonical UUIDv4 JSON-RPC ID, protocolVersion `2025-06-18`, clientInfo and client
capabilities. This narrow binding advertises no optional client capabilities (`{}`).
The immutable request belongs to this session only. Sending moves the client to
WAIT_INITIALIZE; the server expects initialize as its first MCP interaction.

The authenticated reply MUST match both the outer request and the inner JSON-RPC ID.
A successful result selects `2025-06-18`, includes serverInfo and advertises exactly
`capabilities: {"tools": {}}`. Dynamic list changes, sampling, prompts, resources,
logging, experimental features and elicitation are not negotiated in this binding.
A protected JSON-RPC error, unsupported version or capability mismatch aborts setup;
no fallback, retry on the same session or partial readiness is permitted.

A successful initialize or discovery response also requires outer `success: true`
and no outer error. A false/error carrier never becomes setup success even if its
plaintext looks successful.

A successfully validated reply moves the client to INITIALIZE_ACCEPTED. The server
moves to WAIT_INITIALIZED only after the initialization reply for that immutable
invocation clears OUTPUT_PENDING with successful local send and final checks. The client does not dispatch tools in either state.
Duplicate initialize, out-of-order lifecycle messages and mismatched replies close
setup. Failure is locally observable without exposing detailed authentication oracles.

## MSET-04 — Initialized notification and transport acknowledgement

The client then sends exactly the MCP notification
`{"jsonrpc":"2.0","method":"notifications/initialized"}` in a fresh encrypted outer
request. This draft chooses the no-params form. It has no JSON-RPC ID and receives
**no JSON-RPC response**. The outer request is only a carrier with normal replay and
request correlation. The client enters WAIT_INITIALIZED_ACK.

In WAIT_INITIALIZED, the server authenticates and validates the exact notification,
confirms the local immutable setup state and prepares its protected endpoint. It
returns one signed, encrypted outer response with `success: true`, no error member,
and plaintext exactly the two UTF-8 bytes `{}`. That fixed marker means only
"this notification was accepted in this connection's initialization state".
It is not a Guard result, execution success, capability or model-visible content.
`data` is the encoded encrypted session record, never literal empty outer data.

The client validates signature, AEAD, session, exact original request_hash/message_id,
outer success and exact `{}` plaintext before entering NEGOTIATED. Any other plaintext,
MCP response object, error, wrong correlation or second response is rejected. The
server enters DISCOVERY_ONLY only after the acknowledgement clears OUTPUT_PENDING
with successful local send and final checks. If sending fails
or its outcome is uncertain, close the connection; do not resend or create a second
acknowledgement. Accepted replay records remain consumed.

Loss of the acknowledgement leaves the client unready. The server may be further
advanced but MUST NOT dispatch without the remaining local admission rules. This
protocol does not promise simultaneous knowledge or exactly-once network delivery.
A new connection may recover by fresh setup; no tool effect occurred in this phase.

## MSET-05 — Protected tool discovery and readiness

NEGOTIATED/DISCOVERY_ONLY permit exactly one authenticated `tools/list` request and
correlated response before protected operations. The request has exactly jsonrpc, a fresh UUIDv4 id and method `tools/list`, with
no params, cursor or extra members. The successful JSON-RPC response has exactly
jsonrpc, that id and result; result has exactly tools. Its one tool object MUST equal
the complete JCS of the [pinned descriptor](tool.json), including the exact member
set, not just a projection of name/inputSchema. Reject nextCursor, outputSchema,
annotations, descriptions, titles and unknown metadata in this narrow discovery
binding. Received schema never replaces the trusted baseline.

General MCP permits additional tool description fields, including outputSchema;
this restriction is a deliberate smaller binding, not a statement that those fields
are invalid MCP. See [MCP tool definitions](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
Extending this descriptor requires an explicit baseline/profile revision.

The client becomes READY only after successful schema and response verification.
The server becomes READY only after its listing response clears OUTPUT_PENDING
with successful local send and final checks, and its local protected endpoint, schema
and mediation are installed. A peer-supplied tools
capability alone cannot establish that local fact. If discovery fails, close setup.
This deliberately restricted one-tool, fixed-schema binding does not advertise full
MCP service interoperability. Broader discovery requires a separate profile revision.

Only READY permits `sage_secure_call` through the Guard boundary, with the existing
exact-intent, policy, manifest, nonce, ledger and result checks. Readiness is necessary
but never sufficient authorization. No direct tool route, recursive secure call,
notification-style protected call or downgrade is introduced. Server/client local
states need not advance simultaneously; each applies its own admission predicate.

## MSET-06 — Deadline, failure and resource ownership

Each side sets a trusted monotonic setup deadline no later than **30 seconds** after
its local SAGE channel key-state creation. The responder starts while provisional;
confirmation does not restart the deadline. Handshake and session expiration may
close earlier. At or after the deadline no new setup transition or transition into READY
is allowed. Local policy may shorten it. Peer timestamps, traffic or progress never
extend it. A missing, untrusted or backward-moving monotonic clock closes setup.
Immediately before publishing every transition, including after validation, gate
preparation and local I/O, re-read that clock and recheck deadline, session validity,
owner liveness and closure under the serialized owner. A concurrent timeout or close
wins over any later completion callback; CLOSED cannot publish READY. Starting a
callback before the deadline does not allow completing its transition after it.
Every blocking callback is bounded by the remaining deadline, not merely
checked after return. A setup timeout closes the SAGE connection and discards local
readiness and pending response handles without resetting replay state.

Any authentication error, invalid state, unsupported setup, cancellation, uncertain
send outcome, resource exhaustion or failure to prepare the local gate closes this
setup and denies all protected calls. Implementations may report a generic failure;
this binding does not require fabricating a protected MCP error after an invalid
message. No error response is promoted into a signed Guard rejection/completion.
A fail-closed decision cannot be overridden by an LLM option or user-confirmation flag.
Session record and endpoint attempt limits remain applicable; new instances cannot
reset an existing session's counters or deadlines.

## MSET-07 — Closure and reconnect

Close, key revocation/material change, expiry, owner loss, role/peer/session change
or an interrupted initialization retires readiness. Recovery creates a new authenticated
channel and complete setup. No old initialize response, notification acknowledgement,
listing result or local readiness handle can activate it. Outstanding protected calls
at closure are unresolved until application-level reconciliation; no automatic redispatch.

A fresh connection does not change signed Guard call identity or release intent nonce,
execution reservation, terminal result or durable client consumption. Reconnect must
preserve these independent states. Never recreate a missing ledger as empty merely
to restore readiness. Client-result restart evidence does not certify transport replay
recovery or host-wide exclusive ownership.

## MSET-08 — Adoption and excluded HTTP behavior

This proposal selects non-HTTP behavior only. It does not define chapter 08 HTTP
intent/RPC mapping, HTTP version-header signing, MCP HTTP session management or OAuth
integration. Those remain separate OPEN design work; failure here cannot fall back
to an unspecified HTTP or unprotected route.

Before adoption: independently review this state machine and fixed acknowledgement;
update the normative profile, traceability and compatibility/change record together;
adopt the pinned schema baseline explicitly; then add core APIs and Inspector vectors. Existing
version-string constructors must remain described as trusted-host inputs until an
unforgeable session-owned readiness path is implemented and tested. Old runtime
reports, 37 lifecycle NOT_RUN outcomes and conformance NOT_ESTABLISHED are unchanged.

## State summary

| Client | Accepted next event | Next state |
|---|---|---|
| CHANNEL_AUTHENTICATED | emit initialize | WAIT_INITIALIZE |
| WAIT_INITIALIZE | authenticated matching initialize success | INITIALIZE_ACCEPTED |
| INITIALIZE_ACCEPTED | emit initialized carrier | WAIT_INITIALIZED_ACK |
| WAIT_INITIALIZED_ACK | authenticated fixed acknowledgement | NEGOTIATED |
| NEGOTIATED | emit tools/list | WAIT_DISCOVERY |
| WAIT_DISCOVERY | authenticated pinned tool schema | READY |
| setup state, including OUTPUT_PENDING | setup deadline or validation failure | CLOSED |
| any nonclosed state, including READY | session invalidation or explicit close | CLOSED |

Server progression is EXPECT_INITIALIZE → WAIT_INITIALIZED → DISCOVERY_ONLY → READY,
with transitions after authenticated input, successful bounded local output and
final serialized checks as specified above. Each output passes through OUTPUT_PENDING;
the table lists stable states only. All other setup events close the connection. No transition leaves
CLOSED. Once READY, setup timeout is no longer a traffic timer; normal session and
Guard limits apply. Re-initialization on a READY connection is rejected and closes it.


## Review disposition

The [counterexample review](review.md) identifies five ambiguities in the first
published draft and maps their corrections to nine additional planned cases. It is
a separate review pass by the same authoring agent, not an independent external
reviewer, formal proof or real MCP runtime result. All 40 planned cases remain NOT_RUN.
The [review record](review.json) binds the reviewed revision and corrected artifacts.
