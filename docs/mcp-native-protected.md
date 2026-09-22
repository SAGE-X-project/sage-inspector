# Native protected MCP interoperability

The private [native setup bridges](mcp-native-setup.md) now support a protected
execution mode. Inspector runs Go/Go, Go/Rust, Rust/Go and Rust/Rust using the same
signed intent, native connection owner, fixed execution worker and owned client
path. It does not replace encryption, signing, admission or delivery with an
Inspector implementation. The pinned core revisions are unchanged.

```sh
python3 -B scripts/test_mcp_protected.py
python3 -B scripts/run_mcp_setup_interop.py --protected \
  --go /path/to/sage --rust /path/to/rs-sage-core \
  --output /tmp/new-native-mcp-protected
```

Use the same POSIX, Python, Node, toolchain and dependency prerequisites as the
setup runner. Outputs must be new and outside all repositories. CI runs both the
setup and protected matrices and uploads them together as
`mcp-native-interop-<revision>` artifacts. Source snapshots, test overlays, dependency
locks, executable hashes, raw frames, observations and journals are preserved.
The added checker fixture is captured public-test-key traffic for regression
controls; it is not independent evidence of protocol conformance.

## Actual execution and independent checks

The intent authorizes the fixture's inert `read` operation with the fixed argument
`{"path":"public.txt"}`. No file or external tool is actually read. Both executors
return `{"text":"inert public fixture"}` and count one in-process effect. The client
accepts pending responses and polls at most four times in total. A shared controlled
fixture clock starts at Unix 460 / monotonic 360000 ms and advances one second before
another poll, satisfying the native client's minimum polling interval. Registry
observations use the corresponding current test time. This is a controlled schedule,
not verification of all clock races or deployment clock synchronization.

The controller observes a completed first terminal delivery and a rejected subsequent
exchange. It requires the wire exchange count to match client journal sends and
consumption records; this detects a purported local rejection that actually sent
another request. The server must record exactly one effect. Clean peer EOF ends the
server receive loop, and both hosts must finish their owned cleanup. Missing or failed
bridge tests cannot pass. There are at most eight frames per direction including
setup; incomplete frames, excessive exchanges and process timeouts fail the run.
The relay only forwards captured bytes and never injects a mutated message.

The independent checker verifies:

- Setup signatures, transcript/session identity and encrypted request/response bindings.
- Protected outer signatures, context, session, peer, key, request hash and unique
  wire identities; pending versus completed outer status.
- The common intent signature and exact intent bytes in all execution journal rows.
- Exactly `RESERVED`, `EXECUTING`, `COMPLETED` for the one durable operation.
- Matching terminal result bytes in the server ledger and client journal, and the
  result signature, intent digest, request/call identities, time bounds and output.
- One client open, one send/close pair per exchange, and one terminal tied to the
  final consumed invocation. The delivered output must match that signed result.

Checker rejection tests change only local captured observations or journal fixtures.
They cover duplicate effects, wrong output, missing consumption, altered transitions,
result disagreement, wire binding mismatch and invalid signatures. They never transmit
those altered inputs to a running peer.

## Limits and remaining work

A passing report establishes these bounded happy-path protected exchanges and selected
journal assertions. It does not independently decrypt inner RPC ciphertext, prove the
entire journal implementation, test restart recovery, verify a live registry/blockchain,
or provide host/plugin mediation guarantees. Go's replay journals and Rust's existing
in-memory replay fixture retain their previously documented limitations. Execution
and client journals in this run are real core journals.

The historical 71 catalog cases and 26 mandatory child obligations remain unpromoted;
conformance remains NOT_ESTABLISHED. Next add bounded recovery/reopen observations and
case-specific scheduling checks, preserving this distinction between actual execution,
checker regression tests and full normative coverage.
