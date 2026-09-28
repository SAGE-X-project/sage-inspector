# Current-spec WebSocket and local receive boundary

TRANSPORT-06 carries one signed UTF-8 JSON envelope per reassembled WebSocket
text message over authenticated TLS. Binary messages and per-message
compression are disallowed, and the cumulative reassembled limit is 16 MiB.
A trusted connection or local hook cannot replace per-envelope verification;
the signed recipient and payload, rather than the connection URL, determine
the logical target.

Five [declarative cases](../vectors/0.10.0/transport06-scenarios.json) cover a
fragmented signed text message, compression negotiation, binary delivery, a
16 MiB plus one cumulative fragment length, and an unsigned local envelope.
Four supplemental controls cover a signed local envelope, a wrong expected
recipient on an authenticated connection, an unsigned WebSocket message on
that connection, and the exact 16 MiB size gate. The large-size cases use
compact lengths; they create no oversized payload or network traffic. The
unit checker independently verifies the signed source envelope and keeps
framing, recipient, and signature decisions distinct.

The [preserved 185-case Go/Rust run](evidence/current-spec/transport06/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`8d0901ab8c6b3d229406445cc5b3d0e70c37b2d6`. Reassess fixture, runner,
binary, and observation hashes with
`python3 -B scripts/check_current_spec_transport06_evidence.py`.

Neither current core primitive adapter exposes the integrated WebSocket or
local WireTransport receiver. All five case bindings are `UNSUPPORTED`. A
separate [in-memory event run](evidence/current-spec/transport06/events/report.json)
reassembles one fragmented text message and rejects compression negotiation
and a binary event in the Inspector parser; both cores verify the positive
message's Ed25519 signature as an isolated primitive. This local run used
wsproto 1.2.0 and h11 0.14.0, with no TLS socket or receiving core. The
older [WSS interoperability record](websocket010-bindings.md) uses different
core revisions and a 32 KiB Inspector message cap, so it is not promoted to
current-spec 16 MiB or end-to-end conformance evidence.

Actual 16 MiB reassembly, authenticated TLS at the current binding, local
unavoidable verification, recipient enforcement, replay state, and protected
dispatch remain unverified. Full TRANSPORT-06 conformance is
`NOT_ESTABLISHED`. Across all 481 cases, Go has 18 `FAIL`, 134 `UNSUPPORTED`,
33 `PARTIAL`, and 296 `NOT_RUN`; Rust has 12 `FAIL`, 133 `UNSUPPORTED`, 40
`PARTIAL`, and 296 `NOT_RUN`.
