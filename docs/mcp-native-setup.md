# Native MCP setup interoperability

Inspector's test-only bridges exercise the pinned cores' actual owned TCP
connection path in four combinations: Go/Go, Go/Rust, Rust/Go and Rust/Rust.
Each side performs an authenticated completion handshake and encrypted MCP
initialize, initialized acknowledgement and discovery before its connection
handler can publish READY. This advances beyond the selected single-core tests
in [runtime evidence](mcp-core-runtime.md).

The inputs are Go `e750b2ab2f901b250af4805a9b8c6266752bdfc2` and Rust
`24626154967dc3bc85ad1a69da34011e3a1f5dc5`. Inspector archives those commits,
adds its bridge only to temporary test snapshots and appends one Rust test-module
declaration. Production core source and public APIs are unchanged. Reports retain
both original source archive hashes and added bridge hashes; these executables are
test-instrumented builds, not untouched release binaries. Go runs with race detection.

```sh
python3 -B scripts/test_mcp_setup_interop.py
python3 -B scripts/run_mcp_setup_interop.py \
  --go /path/to/sage --rust /path/to/rs-sage-core \
  --output /tmp/new-native-mcp-setup
```

Use a POSIX host, Python 3.10+, Node.js, compatible Go/Rust toolchains and cached
Rust dependencies. Python optimization is unsupported because the reused independent
completion verifier relies on assertions; validation explicitly fails under `-O`.
The output directory must be new and outside Inspector and both core repositories.
CI prepares dependencies, runs the actual bridges on Linux and preserves evidence
in `mcp-native-interop-<revision>` artifacts.

## Observations

A passive local relay forwards the exact four-byte length prefix and frame bytes.
It never re-signs, replaces or injects a message. Capture is bounded to the handshake
and three setup exchanges, each envelope limited to 32768 bytes. Each pair retains
eight raw frames, both peer logs and READY observations. An independent Node Ed25519
implementation verifies nine signatures per pair, including completion's inner
signature. The checker derives the transcript hash/session ID and checks context,
peer identity, role, version, key ID, response success, request hashes, encrypted
setup carriage and nonce uniqueness. It does not decrypt captured setup ciphertext;
inner setup acceptance is observed through the native core's READY transition.

Both peers remain alive until the controller observes READY, then receive a local
release signal. A peer close after release may race the other core's final liveness
check. The bridge does not claim post-release delivery: it requires READY before
release, successful host cleanup and exactly one passing selected bridge test per
process. Missing, skipped or failed tests cannot pass the report. Setup and rendezvous
have fixed deadlines, and unfinished process groups are killed and logged. Build
processes have a 600-second bound; pair process execution is bounded separately.
Failures preserve already captured frames and logs in a FAIL report.

The fixture uses public test keys (Ed25519 seeds 1 and 2, responder X25519 seed 3),
controlled registry observations and fixed trusted clocks at Unix 460/monotonic
360000 ms. Rust's existing replay fixture is in memory; Go uses its existing replay
journal after startup quarantine. These different test stores do not establish
durable replay equivalence. No real blockchain, live registry, external tool or
host-bypass program is involved.

## Remaining scope

PASS means native authenticated setup interoperability for these four happy paths.
It does not execute protected tool calls, independently inspect inner plaintext or
journals, verify every deadline/closure schedule, or establish deployment conformance.
The historical catalog remains 71 NOT_RUN and its 26 mandatory child obligations
are not promoted. Historical reviews and reports retain their original revisions.

The [protected interoperability extension](mcp-native-protected.md) now adds a
common signed intent, inert bounded effect, result delivery and selected journal
assertions across the same four combinations. Add per-case negative and scheduling evidence
only with complete actual bindings and independent observed assertions.
