# Pinned MCP core runtime evidence

Inspector can now build and execute selected private owner/transport tests from
exact core commits. This is a test execution adapter, not an external protocol
adapter or a Go/Rust interoperability result. It deliberately uses the existing
private core path rather than exporting session keys, resettable history or an
alternate sender for verification.

Inputs are Go `872307563416f144cc863d26b594b0ce7da1f2bd` and Rust
`8d91b2f85fb887f827bff752171315a57fd694ce`. The runner archives these exact commits
and builds temporary copies. Dirty and untracked working files are not used or
modified. The old [owner review](mcp-owner-core-review.md) and
[proposal catalog](mcp-consolidated-catalog.md) remain historical records at their
original revisions.

For each core, the selected tests exercise an actual authenticated loopback
handshake, setup and protected exchange; a stalled handshake retaining connection
capacity; and capacity retained through socket or endpoint cleanup. These are
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
is a separate manual command requiring the pinned repositories and dependencies.

The report's PASS means only that all six selected core assertions executed and
passed. Raw protocol frames, complete journals, callback identities and independent
wire assertions are not collected by this adapter. Accordingly, interoperability
remains NOT_RUN, conformance remains NOT_ESTABLISHED, all 71 catalog cases remain
NOT_RUN and the 26 mandatory child obligations are not promoted.

Next implement a private test-only peer bridge for each core that retains the actual
owner and sole transport path. Then execute Go/Go, Go/Rust, Rust/Go and Rust/Rust
sessions and independently inspect raw messages, journals and bounded effect counts.
Only cases with complete bindings and observed assertions can change status.
