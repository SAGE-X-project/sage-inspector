# Concurrent cross-core record inspection

The `sage-exchange -concurrent` mode invokes the real legacy receiver API from
multiple Go goroutines or Rust threads sharing one session. The archived run has
**224 checks PASS**, with **512 worker observations** and measured call-interval
overlap in all **64 contention groups**. Go was built with `-race`; no detector
error was reported in this run. These are bounded observations, not an exhaustive
proof of every scheduler interleaving or whole-protocol conformance.

```sh
go build -o /tmp/sage-exchange ./cmd/sage-exchange
# Build the Go adapter with -race; build Rust with cargo build --locked.
/tmp/sage-exchange -concurrent \
  -go-adapter /absolute/path/to/go-adapter \
  -rust-adapter /absolute/path/to/rust-adapter \
  -go-revision ACTUAL_GO_COMMIT -rust-revision ACTUAL_RUST_COMMIT \
  > /tmp/concurrent.json
```

`-concurrent` and `-stateful` are mutually exclusive. Process time/output bounds
and executable checks remain enforced by the existing external adapter transport.
The new `parallel_open` action is an explicit bounded batch action, not a new
schema2 virtual-clock or host binding. It accepts 2–16 worker inputs of at most
2048 bytes. The fixed inspection uses eight workers.

## Inputs and checks

Go→Rust and Rust→Go are each exercised with c2s and s2c roles. A sender produces
five actual encrypted records from public test inputs. Each of the four directions
runs eight rounds, each with a fresh receiver. State survives all actions within
one round:

| Action | Required observation |
|---|---|
| Release eight workers: four copies of record 0 and four altered copies of record 1 | Exactly one record-0 worker recovers `a`; every altered record is rejected |
| Open intact record 1 | Recover `b`; invalid concurrent attempts did not consume it |
| Open record 0 again | Reject the already accepted record |
| Release eight workers: four copies each of records 2 and 3 | Exactly one worker per distinct record recovers `c` or `d` |
| Open record 2 again | Reject duplicate |
| Open record 3 again | Reject duplicate |
| Open previously unused record 4 | Recover `e`; receiver remains usable |

There are 64 group checks plus 160 sequential checks: 224 total. The 512 workers
are a different counting unit and must not be added as extra protocol cases.
Neither adapter adds a replay cache or a lock around the receiver API. The existing
core's own locking and verdicts determine acceptance.

## Evidence of concurrent pressure

Each worker reports readiness before a common start gate. Only after all eight
workers are ready is the gate released. Immediately around the core API call,
workers record monotonic start/end offsets. Offsets share one origin per group;
they cannot be compared across processes, hosts or groups. The report preserves
worker indices, timing intervals, actual verdicts and recovered plaintext.

Inspector checks both the readiness count and actual overlapping call intervals.
If functional outcomes are correct but no interval overlap is observed, that group
is INCOMPLETE, not a core failure and not a concurrency PASS. The supplied tests
exercise this distinction. A gate declaration alone is insufficient. Overlapping
API intervals include contention on the core's internal locks; they do not prove
simultaneous execution inside a locked critical section. No artificial Inspector
sleep or serialization is used to manufacture the core's acceptance behavior.

The winner is nondeterministic. Verification checks input-to-worker attribution and
one winner per valid record, rather than requiring a particular worker to win.
Accepting a corrupted worker, two winners for one record, missing workers, incorrect
indices, altered plaintext or inconsistent timing evidence fails the relevant check.
A process error never becomes a successful rejection; absent producer data leaves
the corresponding receiver checks NOT_RUN. No retry loop selects only passing runs.

## Reproduction and remaining scope

`docs/evidence/deployment/concurrent.json` contains the live requests and observations.
`concurrent-provenance.json` pins source files, core source lock, executable/build
identity and race-detector configuration. The evidence catalog and integrated
report link this run separately from previous stateless and sequential reports.
All planned normative case statuses remain unchanged.

```sh
python3 scripts/check_concurrent_evidence.py
python3 scripts/test_concurrent_inspection.py
python3 scripts/test_parallel_adapters.py /path/to/go-adapter /path/to/rust-adapter
```

CI validates archived byte forwarding, complete direction/round membership, actual
winner constraints, timing evidence and mutation tests. Go orchestration tests
include unsupported adapters and serial observations. CI success does not claim a
fresh core contention run on its runner.

This completes the bounded duplicate/distinct/invalid-record contention probe.
Expiry, crash/restart recovery, close-versus-receive races, full transcript-bound
HPKE/HTTP/WS exchange and actual Agent host bypass evidence remain outstanding.
INS-11 remains in progress and `conformance` stays `NOT_ESTABLISHED`.
