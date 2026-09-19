# Guard client consumption and polling

The two cores now provide a protected client tracker for one operation, backed by a
separate interoperable journal. It records the unchanged canonical original, used
outer UUIDs, consumed transport invocations and first terminal. Each deployment must
maintain a stable issuer/call-to-journal mapping and never initialize a second tracker
for the same operation. Normal reopen cannot create missing state or redeliver output.

Begin rechecks intent authentication, current policy and expiry, persists the outer
UUID and calls a bounded trusted sender under the same lock used by Accept. The
sender must perform exactly one protected handoff with the original envelope and
fresh transport metadata; delayed duplicate sends are forbidden. Both UTC and
monotonic time must advance at least 1000ms from handoff completion. Reopen imposes
an additional one-second monotonic wait. Failed sends remain unverified and do not
create another call identity, terminal verdict or read-only reconciliation promise.

Accept consumes one private outstanding invocation. It verifies the active executor,
recipient, IDs, exact intent digest and result validity before making a result usable.
Pending has no output; the first terminal is stored before output release. Delayed
pending and identical terminal from other outstanding invocations are ignored, and
conflicting terminal bytes cannot replace the first. Terminal or intent expiry stops
new polling, while fresh replies to already accepted invocations may arrive later.

Persistence before output release provides at-most-once delivery, not exactly-once
application effects. A crash or final validity failure can lose delivery and requires
protected reconciliation. Corrupt/missing journals and failed clocks deny; poisoned
writer locks require administration. Filesystem integrity, anti-rollback, real transport
binding and host isolation are deployment boundaries, not properties of fixture flags.

## Independent tests and runtime evidence

`generate_guard_client_vectors.js --check` independently reconstructs the frozen
19 scenarios and deterministic Ed25519 fixture signatures with Node/OpenSSL. Both
cores execute the same bytes in native tests. Cases include 999/1000ms, independently
advancing or backwards clocks, expired/revoked results, late pending, conflicting
terminal, invalid/unsolicited replies and lost transport responses. Additional native
tests exercise concurrency, send duration/uncertainty, exclusive/missing/corrupt
storage and failure or expiry between persistence and delivery.

The Go and Rust `guard-client010` adapters call only actual core APIs and use an inert
protected sender that records the exact handed-off identity, bytes and count. Their
trusted clock/key/policy controls are bounded test services, never production peer
inputs. They accept at most 64 local JSONL commands of 4 MiB each; the driver imposes
a process timeout. No external tool, network attack or host bypass is executed.

`test_guard_client010.py` executes 64 processes: 38 scenario processes, eight processes
for four real server-to-client signature exchanges, 16 processes for eight client
journal recovery combinations, and two missing-state controls. Each Go/Rust pairing
covers unresolved and consumed-terminal reopen. Real server results use the earlier
result publication APIs and are independently checked by Node/OpenSSL (16 signature
checks). The fixture-only sender measures handoff behavior, not production transport
or actual registry deployments.

Reports retain 128 hashed files containing commands, exit/stdout/stderr, journals and
signature audit inputs/results, with core revisions and adapter/fixture hashes. Offline
report tests reject altered counts, identities, timestamps and duplicate output.
CI preserves these in a separate `guard-client-bindings` artifact. The earlier server
and record reports retain their original meaning. All 37 full Guard lifecycle
scenarios remain NOT_RUN and overall conformance remains NOT_ESTABLISHED.

## Reproduction and next work

Build the client and result-server adapters against `test_record010_adapters.py` pins.
Run the fixture checker and `python3 scripts/test_guard_client_reports.py`, then:

```sh
python3 scripts/test_guard_client010.py --go /path/to/sage-guard-client010 \
  --rust /path/to/guard_client010 --go-server /path/to/sage-guard-results010 \
  --rust-server /path/to/guard_results010 --output /new/evidence/directory
```

`--development` explicitly permits unpinned checkouts; final evidence and CI do not
use it. Historical evidence is preserved. Next is MCP result mapping and its closed
representation/version checks, followed by full lifecycle integration and the remaining
deployed Source/host bindings. These results do not certify those unfinished pieces.
