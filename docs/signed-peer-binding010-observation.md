# Signed sender and peer binding at handshake receipt

The [six-case suite](../vectors/0.10.0/signed-peer-binding010.json) fixes
expectations from `sage-spec` revision
`fa006fd917ad365eb554a27f4178301cd66e2379` for ID-03,
TRANSPORT-01/02/04 and HPKE-02. It runs one positive signed request and five negative
requests through both Go and Rust 0.10.0 completion receivers in all four
sender/receiver combinations.

Each negative request is signed with an explicitly public test seed. The
suite checks a sender DID and key URL that disagree with the handshake,
a key URL or recipient that disagrees with the handshake, a signature made
by another registered test key while the request names Alice, and a request
addressed to a peer other than the receiving Bob endpoint. Independent Node
verification confirms that each changed request has a valid signature for
its stated test signer; the other-key case deliberately names Alice while
using Bob's key. The positive case also checks the response and completion
signatures independently.

Local bounded execution matched **24/24 cases** at Go
`fbd9b2169c72d62c62dcbaa2336275d08a5735a8` and Rust
`0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f`. Accepted requests
created one handshake reservation. Rejected requests produced no session
and no handshake reservation. The report records the exact suite, fixture,
core revisions, adapter hashes, request hashes and raw process transcripts.
CI rebuilds both adapters from pinned revisions and preserves its report.

The Source, Clock and replay store are controlled local test dependencies.
This observation covers the plain completion request boundary, not every
HTTP, WebSocket, MCP, Card or execution-intent binding. It does not prove
deployed Registry authority, host isolation or full ID-03 conformance. The
complete 0.10.0 parent cases remain `NOT_ESTABLISHED`.
