# HTTP session signature bindings

The Go and Rust cores now bind authenticated session requests/responses to the
bounded canonical RFC 9421 profile described in their `HTTP010.md` documents.
The completion handshake remains separate. This report does not certify a full
HTTP server, TLS, WebSocket, persistent replay service or production registry.

The core verifies exact Content-Digest before JSON parsing, outer signature and
header/envelope agreement, inner signature, current pinned keys, AEAD and retained
request correlation before one replay/sequence/terminal publication. A permanent
HTTP binding rejects bare session API calls. Responses use privately retained
original request components, including the exact Signature field, for `;req`.

The profile admits canonical Structured Fields with arbitrary parameter order,
HTTPS POST to a configured canonical endpoint, Ed25519, 32 KiB content, 32 KiB
fields and 8 KiB signature fields. Alternate RFC serialization, general methods,
URI normalization, raw HTTP framing and handshake carriage are not implemented
by this API. Adapters supply synthetic trusted transport metadata; peer-provided
JSON is never an acceptable production substitute for transport-derived metadata.

## Independent checks

- `vectors/0.10.0/http-session010.json`: 45 shared core unit scenarios; additional
  size/parameter boundary unit checks are kept in each core.
- `scripts/test_http_session010.py`: 180 real local-process scenarios across
  Go/Go, Go/Rust, Rust/Go and Rust/Rust. Python constructs bases independently;
  Node crypto checks both signatures using public fixture keys. Altered profile
  parameters are re-signed where appropriate, distinguishing schema/binding
  rejection from merely invalid cryptography.
- `scripts/test_http_session010_unit.py`: five checks of the independent base,
  exact retained signature, validly signed wrong method, digest mismatch and
  duplicate preservation. A fixed SHA-256 literal anchors the body digest check.
- Runtime assertions observe no reservation on invalid input, successful retry,
  one reservation on valid acceptance and no second reservation on replay.
  Reordered parameters, signed application errors, reverse direction, tampered
  status, independently re-signed invalid inner messages, retained request
  signature mismatch, store failure/delay, expiry and key revocation are covered.
- `http-session010-reference.json` pins the local RFC text, legacy implementation
  and SAGE chapter 03. Legacy reference code is not used as an expected-result
  oracle. Historical HTTP FAIL/UNSUPPORTED and other archived findings remain.

Only bounded local processes and synthetic dependencies run. There are no external
network targets, production credentials or host-bypass/reproduction programs.

Pinned Go core: `a36a90fa6dabcab972b25e2f06f008a87ce82199` (PR 337).
Pinned Rust core: `47512577540d835711b71ab74cd26a6b7433dc66` (PR 49).

## Reproduction and evidence

Build the existing Go `cmd/sage-completion010` and Rust `completion010` adapters
against revisions pinned in `scripts/test_record010_adapters.py`, then run:

```sh
python3 scripts/test_http_session010_unit.py
python3 scripts/test_http_session010.py --go /path/to/go-adapter --rust /path/to/rust-adapter --output /new/output/http-session010
```

The default run requires clean tracked core sources at the pinned commits and
identical shared fixtures. `report.json` records core revisions, executable and
fixture hashes, per-exchange signature-base hashes, and the SHA-256 of `raw.jsonl`.
The raw log preserves bounded control inputs, replies and process exit evidence.
`--development` explicitly marks exploratory unpinned results; CI never uses it.
Full protocol conformance remains `NOT_ESTABLISHED` even when all scenarios PASS.
CI preserves the ninth report group, `http-session010`, in the existing record
binding artifact alongside prior completion/record/response regression evidence.

## Remaining work

1. Integrate a trusted raw HTTP/TLS adapter that preserves duplicate fields and
   verifies actual routing/framing, and extend handshake HTTP carriage.
2. Broaden or explicitly standardize admitted Structured Fields/URI subsets before
   claiming complete chapter 03 interoperability. Existing full HTTP fixtures are
   not relabeled by these new session-specific results.
3. WebSocket framing and session binding; durable replay/restart quarantine;
   actual authoritative registry and controlled host integration.
