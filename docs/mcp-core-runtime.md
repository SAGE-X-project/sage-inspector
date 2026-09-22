# Pinned MCP core runtime evidence

Inspector can now build and execute selected private owner/transport tests from
exact core commits. This is a test execution adapter, not an external protocol
adapter or a Go/Rust interoperability result. It deliberately uses the existing
private core path rather than exporting session keys, resettable history or an
alternate sender for verification.

Inputs are Go `fb1a00cbda517c069a8b2c7bcad87b7e54a5cc75` and Rust
`c8c9b0c6540a66f8d81e7a49a7631f51517c64b6`. The runner archives these exact commits
and builds temporary copies. Dirty and untracked working files are not used or
modified. The old [owner review](mcp-owner-core-review.md) and
[proposal catalog](mcp-consolidated-catalog.md) remain historical records at their
original revisions.

For each core, the selected tests exercise an actual authenticated loopback
handshake, setup and protected exchange; a stalled handshake retaining connection
capacity; capacity retained through socket or endpoint cleanup; and the four pinned
[owner admission boundaries](mcp-owner-admission.md). These are
bounded trusted fixtures with inert effects. Go executes with the race detector.
The schedules are core-specific and do not establish equivalent behavior for every
normative obligation.

```sh
python3 -B scripts/test_mcp_core_runtime.py
python3 -B scripts/run_mcp_core_runtime.py \
  --go /path/to/sage --rust /path/to/rs-sage-core \
  --output /tmp/new-mcp-core-runtime-evidence
```

Use Python 3.10 or later on a POSIX host, Go and Rust toolchains compatible with the
pinned cores, and pre-cached Rust dependencies (Cargo runs offline). Go may download
its declared dependencies. The output must be new and outside all three repositories.
Builds have a 600-second deadline; each selected runtime test has a 30-second process
group deadline. A timeout kills the local test process group and fails the report.
The runner preserves source archives, its own source, dependency locks, build and
execution logs, executable hashes and Inspector revision/dirty status. Ephemeral
executables and working directories are removed after execution. It does not produce
reproducible-binary claims from source identity alone.

A zero exit code is insufficient: each log must contain exactly the requested test
and a passing result. Missing, skipped, duplicate or failed tests prevent success.
An existing evidence directory is never overwritten. Classifier tests and harmless
local process success/failure/timeout tests run in Inspector CI; core runtime execution
also runs in the native MCP CI job with the pinned repositories and dependencies.

The report's PASS means only that all twenty-eight selected core tests executed and
passed. Raw protocol frames, complete journals, callback identities and independent
wire assertions are not collected by this adapter. Accordingly, interoperability
remains NOT_RUN and conformance remains NOT_ESTABLISHED. The historical catalog stays
71 NOT_RUN. A separate [case evidence overlay](mcp-case-evidence.md) may derive current
per-case results only from exact mapped test logs; it does not alter this runtime
report's historical catalog field or promote the 26 mandatory child obligations.

The [native setup bridges](mcp-native-setup.md) now retain the actual owner and sole
transport path for Go/Go, Go/Rust, Rust/Go and Rust/Rust setup exchanges. Protected
execution, journal inspection, bounded effect counts and completed-journal reopening
are covered separately by the [protected bridge](mcp-native-protected.md).
Only cases with complete bindings and observed assertions can change status.

## Timeout and cleanup schedules

The runner adds four existing safe tests per core to its three transport tests.
It preserves each exact test name, claimed schedule, execution status, return code and
hashed log. `execution_status` retains process timeouts even when the aggregate case
status is FAIL. A zero exit code without the selected passing test is insufficient.
These are assertions executed in pinned core tests, not independent event traces or
newly implemented core behavior.

| Core | Additional schedule | Observed core assertion |
|---|---|---|
| Go | Pipe send/receive cancellation and timeout | I/O settles with an error and a closed stream |
| Go | Queued cancellation and bounded host stop | Queued work has no effect; occupied slots remain charged until the stalled worker terminates; uncertain execution remains UNKNOWN |
| Go | Completed response expiry | Owner closes while COMPLETED state and the one effect remain intact |
| Go | Stalled owner cleanup | Another owner still expires; replacement quota becomes available only after cleanup |
| Rust | Benign fragmented and incomplete input | Complete input succeeds; incomplete input times out with socket closure |
| Rust | Original trusted-clock deadline | Socket closes even if the wall-clock timeout has time remaining |
| Rust | Owner closure during native receive | No client delivery; server stop remains incomplete until its blocked handler returns |
| Rust | Listener dependency cleanup | Listener stops accepting while worker quota remains charged until destructor completion |

Go uses actual in-process pipes, core workers and controlled clocks with race
instrumentation. Rust uses bounded loopback sockets and trusted synchronization
fixtures. No modified attack messages or external targets are used. The scenarios
are not equivalent across languages and do not cover every deadline ordering.

CI preserves these reports separately under `mcp-core-runtime` in the native MCP
artifact. Historical catalog cases remain NOT_RUN and conformance remains
NOT_ESTABLISHED. The case overlay currently has complete evidence for three resolution
cases. Independent per-case evidence and remaining ordering schedules must be added
before promoting any other current result or normative coverage.

## Owner admission schedules

Seven additional tests per core bind durable EXECUTING admission, crash recovery,
close visibility during paused callbacks, owner history and shared-capacity isolation, and suppression
of late protected output without changing the terminal journal. The crash schedule
uses a child test process and temporary journal to leave an admitted EXECUTING row,
then verifies stale-lock rejection, trusted lock recovery to UNKNOWN and zero
redispatch. Each report row records the exact boundary IDs from the hashed contract.
The aggregate report fails if a mapped row omits or changes that mapping. Source identity is audited separately
before the runtime job, and both reports are preserved in the same CI artifact.
