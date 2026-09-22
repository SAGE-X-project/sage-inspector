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
entire journal implementation, verify crash recovery at arbitrary write boundaries, verify a live registry/blockchain,
or provide host/plugin mediation guarantees. Go's replay journals and Rust's existing
in-memory replay fixture retain their previously documented limitations. Execution
and client journals in this run are real core journals.

The historical 71 catalog cases and 26 mandatory child obligations remain unpromoted;
conformance remains NOT_ESTABLISHED. Next add case-specific scheduling checks, preserving this distinction between actual execution,
checker regression tests and full normative coverage.

## Completed journal recovery in new processes

Use `--restart` instead of `--protected` to run the four baseline pairs followed by
four server recovery pairs and four consumed-client recovery pairs. Each pair starts
new client and server OS processes and establishes a new native session. CI runs this
extended matrix. Core revisions and production sources remain unchanged.

The controller copies the completed baseline journals into new run directories and
preserves identical `.before` snapshots. This verifies reopening persisted completed
state, not killing a process during a write or recovering an interrupted filesystem.
The controlled recovery clock is Unix 465 / monotonic 365000 ms, within the intent
and cached result validity windows.

In server recovery, the real admission gate opens the existing ledger with creation
disabled. A fresh client journal sends the same signed intent. The server must return
the already committed result in one protected exchange, record zero new effects,
and leave its ledger byte-for-byte unchanged. The independent checker verifies the
result signature and exact equality with the original ledger's result. This is a
first delivery to a new client journal, not redelivery to a consumed client.

In client recovery, the owned client also opens its completed journal with creation
disabled. Its exchange must be rejected. Capture must contain only the four setup
exchanges, both journals must remain unchanged, and the new server must record zero
effects. Missing observations or failed bridge processes fail verification.

Local-only unit controls reject extra captured traffic, altered journals, unexpected
effects and absent client denial. The report keeps these runtime observations separate
from historical catalog cases and full normative conformance.

## Rechecking saved evidence

```sh
python3 -B scripts/audit_mcp_evidence.py --evidence /path/to/mcp-native-protected
python3 -B scripts/test_mcp_evidence_audit.py
```

The read-only auditor requires a complete `--restart` report with four baseline and
eight recovery pairs. It checks retained file hashes, exact successful bridge logs,
exit codes, setup and protected signatures, correlation, journal transitions and
reported counters. It compares recovery intent bytes and `.before` journals directly
with the corresponding baseline, then rechecks unchanged recovered journals.
Its JSON report goes to stdout; failure returns a nonzero exit code. Python assertion
optimization is rejected because the existing independent crypto checks use assertions.
CI runs the audit after generating native evidence and preserves its result separately.

A changed file with a stale hash fails; recomputing a hash does not suppress the
semantic or baseline-linkage checks. Unit controls alter local saved data only.
Their process logs are synthetic checker fixtures; the real runtime audit is performed
on artifacts generated by actual Go/Rust bridge processes.

This is an offline consistency and cryptographic recheck using the existing Inspector
checker, not a second independent implementation or authentication of artifact origin.
Public fixture keys, editable logs and untrusted hashes cannot prove who ran a test.
It does not validate build provenance, independently decrypt protected inner RPCs or
promote protocol conformance. Inputs should be a stable extracted evidence directory.

Evidence JSON is decoded as UTF-8 and rejects duplicate object keys at every nesting
level, including escaped names that decode to the same key. Non-finite constants and
numbers that overflow floating-point decoding are rejected. This applies to reports,
frame containers, signed outer messages, decoded handshake JSON, observations, intents,
journal rows and decoded signed results. Recomputing a file hash does not make an
ambiguous document acceptable. Local negative controls never transmit altered frames.

Observation and report comparisons preserve JSON value types. Boolean values cannot
stand in for integer effect counts, attempt counts or process exit codes; numeric
values cannot stand in for delivery/denial flags. Journal times and expiry fields
are compared without integer/float coercion, and signed intent/result time bounds
must decode as integers. Local-only controls cover both direct checks and rehashed
saved artifacts through the audit CLI; this does not change core protocol behavior.
