# Go HTTP signature parameter observation

The [new bounded observation](evidence/current-spec/msg01/go-tag-observation.json)
pins Go core revision `5a1b57ff5296a65cf01c03514944629b3c84ae20`
and reuses the independently checked `MSG-01-P` fixture. The Go core now
reconstructs the exact expected RFC 9421 signature base, including the
received `tag` parameter, and verifies the fixture's Ed25519 signature.
Changing only that tag changes the base and invalidates the original
signature. The [earlier assessment](current-spec-msg01-evidence.md) remains
as evidence for its older Go core revision.

This observation checks signature-base construction and one signature. It
does not enforce the SAGE 0.10.0 single-label/closed-parameter policy,
message freshness, complete HTTP framing, Registry key authority, replay,
wire-envelope validation or protected effects. Overall conformance remains
`NOT_ESTABLISHED`. The next core implementation must bind a strict 0.10.0
HTTP verifier to a fresh, authoritative Registry observation before it can
authorize a message; Inspector must then exercise valid pre-expiry and
rejected post-expiry messages against that integrated path.

Run the recorded evidence check and bounded core observation with a clean
Go checkout at the pinned revision:

```sh
python3 -B scripts/test_observe_current_spec_msg01_go_tag.py
python3 -B scripts/observe_current_spec_msg01_go_tag.py \
  --go-root /absolute/path/to/sage \
  --output /absolute/path/to/msg01-go-tag.json
```
