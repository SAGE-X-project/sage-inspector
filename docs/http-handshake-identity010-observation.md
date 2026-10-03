# HTTP handshake identity and signature-role binding

The [nine-case suite](../vectors/0.10.0/http-handshake-identity010.json)
checks the bounded HTTP handshake against `sage-spec` revision
`fa006fd917ad365eb554a27f4178301cd66e2379`, chiefly the HTTP
`X-SAGE-DID`, `Signature-Input` and Ed25519 requirements in chapter 03 and
the handshake boundary in chapter 08. It extends the existing HTTP handshake
suite with exact identity checks in both directions.

The positive exchange independently verifies the HTTP and inner handshake
signatures. Each negative request or response changes one identity-related
HTTP field or signature role. DID header, `keyid` and algorithm cases are
re-signed with the correct public-fixture test seed, so a valid Ed25519
signature alone cannot satisfy the semantic binding. The other-signer cases
use the opposite registered fixture key while retaining the original sender
declaration. An independent Node Ed25519 check confirms the altered HTTP
signature before the receiver runs.
The companion unit test checks that the altered declarations remain
semantically inconsistent even when the HTTP signature verifies.

Bounded local execution passed **36/36 cases** across Go/Go, Go/Rust,
Rust/Go and Rust/Rust at Go
`fbd9b2169c72d62c62dcbaa2336275d08a5735a8` and Rust
`0a6f1e0356f323d6f0bcca5bd96ad3fdab82297f`. A rejected request
created no handshake reservation or session. A rejected response closed
the initiator's pending handshake with no reservation or session. A valid
exchange created one reservation on each side. The runner pins the spec,
core revisions and shared completion fixture; its report hashes the suite,
runner, executables, inputs and raw process transcript. CI rebuilds the
adapters from the pinned cores and retains the report and transcript.

Run with the pinned Go and Rust completion adapters:

```sh
python3 scripts/test_http_handshake_identity010_unit.py
python3 scripts/test_http_handshake_identity010.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --spec-root /path/to/sage-spec \
  --go-adapter /path/to/go-completion-adapter \
  --rust-adapter /path/to/rust-completion-adapter \
  --output /new/output/http-handshake-identity
```

This uses fixed public test seeds and controlled local Registry, clock and
replay dependencies. HTTP objects are synthetic trusted transport inputs;
this result does not establish deployment-level HTTP/TLS routing, Registry
authority, host isolation, MCP bindings or full 0.10.0 conformance. The
parent conformance result remains `NOT_ESTABLISHED`.
