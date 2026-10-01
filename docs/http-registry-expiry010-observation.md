# Protected HTTP requests at registry key expiry

The [bounded input vector](../vectors/0.10.0/http-registry-expiry010.json) checks
the Go core's authenticated HTTP session path at the registered Ed25519 signing
key's expiry boundary. Inspector runs the real Go completion adapter in separate
processes and independently checks each handshake, inner envelope and HTTP
signature using Node crypto. The checked Go core revision is
`59c7d165c4654873c80f0e0a546e6795819ee55e`.

At Unix second 100, the first signed request is accepted. A different signed
request with a new message ID and nonce is rejected at second 101, when the
registered signing key expires. Inspector checks that the receiver returns no
plaintext, creates no new replay reservation and closes the session. A separate
session with the key expiring at second 102 accepts a signed request at second
101. This control distinguishes key expiry from a general clock or record
failure. A fourth process scenario accepts an initial request, then observes
the sender signing key as revoked before a second valid request. The second
request is rejected without plaintext or a replay reservation. This separately
checks the fresh Registry read rather than relying on the key's stored expiry.
The Go core also runs a race-enabled unit regression for the expiry boundary.

The Registry source, trusted clock and replay store in this observation are
synthetic test components. The result establishes this **session HTTP path** at
the pinned core revision; it does not establish a general 16 MiB HTTP verifier,
a deployed authoritative Registry read, application execution authorization or
full REG-05/MSG-04 conformance. The earlier
[operator observation](registry-operator-observation.md) remains a separate,
historical read and management result. Combining these observations does not
prove a live service-to-message authorization chain. Overall conformance remains
`NOT_ESTABLISHED`.

A later [bounded live service observation](live-web-message010-observation.md)
connects authenticated Registry reads to this Go HTTP session path under pinned
local service and Inspector credentials. Its limits and evidence are recorded
separately.

CI builds the pinned Go adapter and preserves the new report and raw process
transcript as an artifact. To repeat the bounded local observation with a clean
Go checkout at the pinned revision:

```sh
(cd adapters/go && go test -race ./cmd/sage-completion010 && go build -o /tmp/sage-completion010 ./cmd/sage-completion010)
python3 -B scripts/observe_http_registry_expiry010.py \
  --go-root /absolute/path/to/sage --adapter /tmp/sage-completion010 \
  --expected-revision 59c7d165c4654873c80f0e0a546e6795819ee55e \
  --output /tmp/http-registry-expiry010
```
