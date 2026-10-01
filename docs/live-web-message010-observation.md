# Live Registry reads before protected HTTP acceptance

The [bounded vector](../vectors/0.10.0/live-web-message010.json) links two
locally running Registry services to the Go and Rust authenticated HTTP session
path. The services publish separate Alice and Bob records under the same
configured web origin. Inspector pins each loopback destination and a temporary
test CA; it does not use DNS or a remote deployment. The source makes a new
authenticated TLS public GET and a separate mTLS inspection read for each
Registry Gate operation. It validates the committed history against the public
record before supplying the exact named keys to the receiving core. A mismatched or
unavailable read fails closed.

Inspector independently checks the handshake and both protected request
signatures. The first request is accepted. Alice then registers a replacement
Ed25519 signing key and revokes the session's pinned signing key through the
service's authenticated management API. Bob rejects a second request that
Alice signed before revocation, returns no plaintext and makes no new replay
reservation, even though the replacement signer remains accepted. The service
revision is `baf5570578ddc19685ebe2a5bda4a284f45c8e05`; the Go core
revision is `59c7d165c4654873c80f0e0a546e6795819ee55e`. The Rust core
revision is `ffa1234720f7a519b753471cfe315605be7deb1c`.
The normative spec revision is `fa006fd917ad365eb554a27f4178301cd66e2379`.

The same acceptance and post-revocation denial are now checked in all four
Go/Rust sender-to-receiver directions. The Rust source uses the core's public
TLS record fetch and history-continuity predicate plus a separately verified
mTLS inspection connection. Its live build uses `adapters/rust-live` so the
older Rust adapter's pinned Cargo lock and evidence remain intact.

Each direction also has a separate service-unavailability observation. After
the first accepted request, Alice signs a distinct second request. Inspector
then cleanly stops Alice's local Registry service while Bob's service remains
available. Bob rejects the second request, returns no plaintext, creates no new
replay reservation and closes the session. The vector and report keep this
case separate from named-key revocation; stopping a local service does not
establish how a deployed chain or network partition behaves.

The recovery sequence starts with the same accepted-request and source-outage
checks. Inspector restarts Alice's service from its existing local journal,
checks that the authenticated version 2 inspection and journal bytes match
their pre-restart values, and updates the pinned loopback
destination. The old session stays closed and cannot accept the previously
denied request. A distinct new Go/Rust handshake then accepts a fresh signed
request. This shows bounded local journal recovery and new-session admission;
it does not show session resumption, rollback resistance of deployed storage,
or readiness of a blockchain source.

This is a controlled integration observation. The adapter's mTLS inspection
credential and two loopback destination mappings are test configuration, not a
general client resolver. The services themselves attest their local committed
histories; independently established deployment storage ownership, clock
assurance, production trust distribution and the general HTTP profile remain
unverified. Overall conformance stays `NOT_ESTABLISHED`.

CI runs the Go adapter's race-enabled unit tests, Rust source and case-selection
unit tests, and twelve loopback TLS scenarios. It preserves revision-pinned reports and raw
process transcripts as artifacts. With clean checkouts at the revisions above,
build both live adapters and run one direction as follows; CI runs all four:

```sh
(cd adapters/go && go test -race -tags liveweb010 ./cmd/sage-completion010 && \
  go build -tags liveweb010 -o /tmp/sage-completion010-live ./cmd/sage-completion010)
cargo test --locked --manifest-path adapters/rust-live/Cargo.toml --bin completion010_live
cargo build --locked --manifest-path adapters/rust-live/Cargo.toml --bin completion010_live
python3 -B scripts/observe_live_web_message010.py \
  --service-root /absolute/path/to/sage-registry-service \
  --go-root /absolute/path/to/sage \
  --rust-root /absolute/path/to/rs-sage-core \
  --spec-root /absolute/path/to/sage-spec \
  --sender-adapter /tmp/sage-completion010-live \
  --receiver-adapter adapters/rust-live/target/debug/completion010_live \
  --sender-core go --receiver-core rust --failure-mode registry-unavailable \
  --output /tmp/live-web-message010-go-to-rust
```
