# INS-05 — State-preserving scenario contract

Tooling schema **2**, protocol **0.10.0**, profile **stateful-scenario**.
This is an Inspector IPC contract, not a new SAGE wire protocol. Schema1 primitive
adapters do not implement it. State-aware Go/Rust subject adapters remain follow-up
work for INS-06..09; the tests in this delivery use an explicitly synthetic counter.

## Execution and isolation

`LoadScenario` freezes a scenario with sources and ordered steps. `RunScenario`
starts one operator-selected trusted process per scenario and retains it for every
step. It sends one newline-delimited request, waits for the corresponding response,
then sends the next step. No expected verdict, output, effect counters or future
steps are sent. The executable hash is checked before launch and recorded.

A step timeout is 1..10000ms of host wall time, including request write and response
read. The entire scenario, including process termination, has a 60s deadline.
Virtual protocol time never replaces these resource limits. Timeout/cancellation
kills the process group and closes pipes. This bounds ordinary trusted adapters;
it does not sandbox a malicious binary or prove host isolation.

At most128 steps, 4MiB fixture/response, 64KiB stderr and32 expected effect counters.
Duplicate/unknown/missing fields, invalid JSON, repeated step IDs, invalid bounds
and mutations of a loaded fixture are rejected. A response must be newline-terminated.
After the last step stdin closes; the adapter must exit successfully without extra
stdout. Logs belong on stderr. Process exit/trailing output can fail the overall
report even if all preceding step observations matched.

## Fixture shape

Root fields: `schema_version:2`, `protocol_version:"0.10.0"`,
`profile:"stateful-scenario"`, `id`, `sources` (same provenance fields as foundation),
`steps`. Each step has `id`, `operation`, `input` object, `timeout_ms`,
`expected:{verdict,output}`, `effects` (exact cumulative counter object).
Only ACCEPT/REJECT are valid expectations; rejection output must be empty.
The whole fixture hash pins sources and expectations. Sources apply to the entire
scenario; a source link does not itself prove independent oracle correctness.

Request example:

```json
{"schema_version":2,"protocol_version":"0.10.0","profile":"stateful-scenario","case_id":"replay","step_id":"retry","operation":"subject.call","input":{"invocation":"same-id"}}
```

Response example:

```json
{"schema_version":2,"case_id":"replay","step_id":"retry","verdict":"ACCEPT","output":{},"effects":{"dispatch":1}}
```

`effects` describes measured cumulative effects since scenario start, not a delta.
The adapter records dispatch counts/arguments at an injected executor boundary;
extra/missing counters also mismatch. Arguments and state snapshots belong in
`output`. REJECT may have nonzero prior cumulative counters, so rejection does not
imply resetting them. Missing instrumentation must return UNSUPPORTED, not fabricated
zeros. Fixture authors must choose counters sufficient for each rejection claim.

## Control operations for state adapters

The runner transports these operations as ordinary ordered steps; the subject
adapter must implement and attest the requested capability or return UNSUPPORTED.
Their input/output schema is pinned in each future operation fixture; Inspector
never implements missing subject policy or cryptography to manufacture success.

| Operation | Control and observation contract |
|---|---|
| `control.clock.set` | Set injected protocol UTC/monotonic clocks to explicit integer values; report values actually used. Do not change machine clock. |
| `control.registry.replace` | Install a synthetic authoritative snapshot including version/finality/freshness metadata; acknowledge exact snapshot identity. No production chain writes. |
| `control.fault.set` | Arm named before/after reservation, commit, persistence or resolver fault; report armed point. An executor restart must preserve the fixture's chosen durable store; restarting the adapter ends the scenario. |
| `subject.parallel` | Run the supplied action group using an explicit barrier/schedule; return per-action IDs/results and aggregate effects only when all actions complete. No serial loop presented as a concurrent race test. |
| `subject.call` | Dispatch one test invocation through actual subject gates; return outcome/state and exact cumulative effects. |

For concurrency the Inspector step is one group transaction: its wall deadline
bounds the whole barrier/action group. The adapter owns scheduling and clock/store
injection. Harness transport alone does not prove that the core actually used an
injected clock, registry or barrier. Reports for real adapters must identify that
instrumentation. Unknown/unavailable controls stop the scenario as INCOMPLETE;
subsequent steps remain NOT_RUN. Concrete operation schemas and real core bindings
are part of the respective HPKE/session/registry/Guard work, not inferred here.

## Results and command

Each step records raw input, compact request SHA-256 (excluding newline), expected
and observed results/effects, duration and PASS/FAIL/UNSUPPORTED/NOT_RUN. The report
records fixture hash, sources, protocol, environment, timestamp and subject revision
and binary hash. Comparison preserves JSON number tokens and array order.
A mismatch, malformed/missing/mis-correlated response or deadline fails and stops
the scenario. UNSUPPORTED stops it as INCOMPLETE. No skipped step becomes PASS.

```sh
go build -o /tmp/sage-scenario ./cmd/sage-scenario
/tmp/sage-scenario -scenario case.json -adapter /absolute/path/state-adapter \
  -subject core-name -revision ACTUAL_REVISION > scenario-report.json
```

CLI exit0: PASS, exit1: observed scenario failure, exit2: configuration/load/start
failure, exit3: INCOMPLETE. JSON goes to stdout only after the run completes;
redirection is shell-managed, not an atomic evidence-file API. Reports are local
unsigned observations, not certificates. No real SAGE stateful conformance is
claimed by this delivery; the386 planned-case statuses remain unchanged.

## Verification

`go test -race ./pkg/conformance ./cmd/sage-scenario` and `go vet` pass.
Subprocess tests verify state retained across steps, expectation non-disclosure,
wrong correlation, unsupported operations, incorrect effects, malformed response,
timeout, nonzero exit and trailing stdout. Loader tests reject schema1, invalid
step deadlines, duplicate step IDs, unknown fields and post-load mutation.
The existing primitive regression suite also passes.
