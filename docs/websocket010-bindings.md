# Authenticated WebSocket envelope binding

SAGE chapter 08 TRANSPORT-06 carries one signed UTF-8 JSON envelope per
reassembled WebSocket text message over authenticated TLS. Unlike HTTP message
carriage, each WebSocket application message uses the transport-independent
wire signature; it is not an HTTPMessage010 or a per-message RFC 9421 field set.
The existing completion and session APIs provide this envelope verification.
No new cryptographic core API or change to the protocol version is required.

## Binding contract

1. Verify TLS server identity before upgrading. Validate the opening handshake
   with a WebSocket protocol implementation, use a trusted configured target,
   and admit no negotiated compression or extensions in this fixture.
2. Reassemble text fragments without invoking the core before the message ends.
   Reject binary messages, invalid UTF-8, non-object or multiple JSON values,
   and oversized content. Control frames never enter the envelope dispatcher.
3. Pass the complete exact bytes to the core: Start/Respond/Complete for the
   authenticated handshake, then SealRequest/OpenRequest and
   SealResponse/OpenResponse for session traffic. Expected recipient and pinned
   signing/KEM identities come from trusted local configuration and the core's
   authenticated tuple, not from the socket URL or upgrade headers.
4. Release application data only after core verification returns success.
   Signature, request hash, AEAD, replay/sequence and provisional confirmation
   remain core responsibilities. A WebSocket connection is not an authorization
   grant and must not substitute for per-envelope verification.
5. Treat close, TLS failure and EOF as local transport outcomes, never signed
   application results. Close pending/session state on transport termination;
   do not complete a pending handshake, downgrade or automatically retry.

The Inspector fixture caps reassembled messages at 32 KiB (stricter than the
spec's 16 MiB ceiling), 64 data frames per message, 16 received messages and
32 control frames per connection. Incoming handshake bytes are capped at 8 KiB
and connection bytes at 256 KiB; bounded reads and worker deadlines also apply.
The socket is loopback-only with fresh temporary CA/server credentials, TLS 1.3,
certificate and hostname verification and ALPN http/1.1. It does not modify the
system trust store. No browser Origin/cookie policy or deployment proxy behavior
is established by this non-browser fixture.

## Executed verification

17 offline unit tests cover the profile event gate and the real wsproto parser:
UTF-8 fragmentation, cumulative bytes/frame limits, exact size, separate messages,
binary and compression rejection, incomplete/invalid JSON, pending fragment
cleanup, upgrade routing, deadlines and malformed frames. Invalid frames are
fixed minimal byte arrays processed only in memory; no socket sends occur in
these tests.

32 real WSS scenarios run the following eight cases across Go/Go, Go/Rust,
Rust/Go and Rust/Rust:

- Successful handshake and encrypted request/response.
- Fragmented messages in both directions.
- Ping/Pong interleaved with fragments.
- Signed encrypted application error.
- A subsequent responder-to-initiator request and correlated response.
- Normal close before authenticated completion, with no core reservation.
- Untrusted certificate and wrong hostname, each before upgrade or dispatch.

Python/Node independently verifies wire signatures and request hashes. Actual
Go and Rust processes perform the cryptographic handshake and session operations;
plaintext and replay counters are checked. Endpoint message hashes must match
in each direction and normal close code 1000 must be observed at both ends.
Existing core failure/replay regression suites remain separate evidence.

Network tests send only ordinary valid WebSocket messages, control frames and
TLS verification failures. They do not send malformed frames, reproduce a host
bypass or target an external service.

## Reproducibility and limits

The transport parser is wsproto 1.3.2 with h11 0.16.0, pinned in
`scripts/requirements-websocket010.txt` and installed into an isolated virtual
environment. TLS uses Python/OpenSSL. This is an Inspector transport fixture,
not a production Go or Rust WebSocket service or evidence about legacy WS code.
The core pins remain:

| Core | Revision |
| --- | --- |
| Go | `80a07b84b9feb739f1a1af8447c92bb55b56baef` |
| Rust | `cc99efe519eed4574437d23b9843d7bddddc0de5` |

Run `test_websocket010_unit.py`, then `test_websocket010.py --go ... --rust ...
--output ...` with the virtual environment's Python. The runner requires these
clean core revisions and creates a fresh output directory. `report.json` records
core/executable/fixture hashes, library versions, public certificate hash,
per-direction message hashes, fragment counts, TLS/close/control evidence and the raw control
log hash. CI adds a twelfth report group, `websocket010`.

Full conformance remains NOT_ESTABLISHED. Historical FAIL/UNSUPPORTED/NOT_RUN
findings are unchanged. Durable replay persistence and restart quarantine,
production registry Source/chain finality, host enforcement, and deployment
transport limits/integration remain separate work. Next is the durable replay
and restart quarantine contract and its safe unit/runtime verification.

References: [SAGE transport chapter](../../sage-spec/spec/08-transport.md),
[RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html), and
[wsproto's public event API](https://python-hyper.org/projects/wsproto/en/stable/basic-usage.html).
