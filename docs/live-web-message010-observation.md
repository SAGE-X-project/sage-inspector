# Live Registry reads before protected HTTP acceptance

The [bounded vector](../vectors/0.10.0/live-web-message010.json) links two
locally running Registry services to the Go core's authenticated HTTP session
path. The services publish separate Alice and Bob records under the same
configured web origin. Inspector pins each loopback destination and a temporary
test CA; it does not use DNS or a remote deployment. The source makes a new
authenticated TLS public GET and a separate mTLS inspection read for each
Registry Gate operation. It validates the committed history against the public
record before supplying the exact named keys to the Go core. A mismatched or
unavailable read fails closed.

Inspector independently checks the handshake and both protected request
signatures. The first request is accepted. Alice then registers a replacement
Ed25519 signing key and revokes the session's pinned signing key through the
service's authenticated management API. Bob rejects a second request that
Alice signed before revocation, returns no plaintext and makes no new replay
reservation, even though the replacement signer remains accepted. The service
revision is `baf5570578ddc19685ebe2a5bda4a284f45c8e05`; the Go core
revision is `59c7d165c4654873c80f0e0a546e6795819ee55e`.
The normative spec revision is `fa006fd917ad365eb554a27f4178301cd66e2379`.

This is a controlled integration observation. The adapter's mTLS inspection
credential and two loopback destination mappings are test configuration, not a
general client resolver. The services themselves attest their local committed
histories; independently established deployment storage ownership, clock
assurance, production trust distribution, Rust parity and the general HTTP
profile remain unverified. Overall conformance stays `NOT_ESTABLISHED`.

CI runs the adapter's race-enabled unit tests and the loopback TLS scenario,
then preserves a revision-pinned report and raw process transcript as an
artifact. To reproduce with clean checkouts at the revisions above, build
`adapters/go/cmd/sage-completion010` from Inspector and run:

```sh
python3 -B scripts/observe_live_web_message010.py \
  --service-root /absolute/path/to/sage-registry-service \
  --go-root /absolute/path/to/sage \
  --spec-root /absolute/path/to/sage-spec \
  --adapter /absolute/path/to/sage-completion010 \
  --output /tmp/live-web-message010
```
