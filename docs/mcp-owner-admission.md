# MCP owner admission and close contract

The earlier [core review](mcp-owner-core-review.md) identified four integration gaps
at Go `be621819...` and Rust `ad30c6a...`. Both cores subsequently added private
owner-aware admission and protected-reply paths. This review pins Go
`49ff23eee9ac270db10fc5f150df9cbe5fc15066` and Rust
`c3b452368e90f0ed8f379e635cfa4070e3c875a1`. It does not reinterpret the older
decision at its original revisions.

The machine-readable
[contract](../verification/0.10.0/mcp-owner-admission-contract.json) binds the exact
implementation and test files, their hashes, thirteen selected tests per core and seven
boundaries:

| Boundary | Required behavior |
|---|---|
| Durable admission | EXECUTING is durable before queue insertion or effect. A failed or uncertain final fence never dispatches; closure after committed admission does not invent rollback. |
| Close linearization | Closure records revocation without waiting for registry, storage, signer, transport or tool callbacks. Final admission and publication recheck the same owner. |
| Owner isolation | Setup and protected IDs remain in one owner history. Shared capacity does not transfer authority or close an unrelated owner. |
| Output publication | Durable completion survives failed or suppressed delivery. A late callback cannot publish, retry, reopen the owner or release occupied quota before termination. |
| READY past setup | READY retires the setup deadline; later protected requests use their own finite request and session limits. |
| Stale setup completion | A repeated setup publication after READY is inert and cannot change readiness, history or operation class. |
| Close before reservation | Closure before protected reservation denies without ledger mutation, trusted-service checks, queue entry or effect. |

## Source and lock review

Go uses `ledger.mu` as the execution mutex and the admission gate mutex as the
coordinator. The documented nesting is execution then coordinator. Registry,
storage, executor, signer and transport work does not run under the coordinator.
Owner closure needs only the coordinator, so it can become visible while one of
those operations is paused. Final admission stores EXECUTING under the execution
mutex, performs the delayed checks, then takes the coordinator to validate the
owner and queue the work. A committed queue entry remains executable after that
owner closes. Protected reply preparation marks one private response identity,
performs storage, signing and transport outside the coordinator, then reacquires
the coordinator for final publication.

Rust separates its execution state, coordinator and queue mutexes. Admission and
reply coordination acquire coordinator before queue; execution storage is held in
a separate phase and is not entered through a queue-to-execution nesting. The
`SetupClose` token records closure independently of endpoint cleanup. Final owner
checks use the private operation identity. Response failure calls the owner failure
path while retaining the durable terminal execution, and queue cleanup happens only
after the bounded callback returns.

These are source-level properties of the pinned private implementations. Hash and
revision checks make source drift fail closed, while selected core tests exercise
the actual scheduling seams with inert counters, temporary journals, controlled
clocks and bounded local callbacks. The tests contain no external target or reusable
attack path. Each crash schedule exits an owned child process after durable admission,
then proves that stale-lock rejection and trusted recovery produce UNKNOWN without
redispatch or effects. The Go close-during-fence schedule directly compares the
protected request ID retained by its owner and the durable nonce retained by the execution
entry across successful, failed and uncertain persistence outcomes. The pre-admission
deadline tests retain the protected request ID and exact intent identity, close the
owner and prove that no effect can run. The post-admission deadline tests fail response
publication while preserving exact journal bytes, durable completion and one effect;
they also reject response and execution retries. The READY-session expiry tests create
a protected request immediately before the idle lifetime boundary, then prove that
session expiry wins while the request's transport lifetime is still valid: admission
is denied, the owner closes, session use is erased and the effect count remains zero.

## Run and interpret

```sh
python3 -B scripts/test_mcp_owner_admission.py
python3 -B scripts/check_mcp_owner_admission.py \
  --go-root /path/to/sage --rust-root /path/to/rs-sage-core \
  --output /tmp/new-mcp-owner-admission-audit
python3 -B scripts/run_mcp_core_runtime.py \
  --go /path/to/sage --rust /path/to/rs-sage-core \
  --output /tmp/new-mcp-core-runtime-evidence
```

The contract audit checks duplicate JSON keys, exact fields, complete per-core
boundary coverage, source hashes and revisions. It reports runtime `NOT_RUN` because
source identity is not execution. The runtime adapter archives the pinned commits,
builds temporary copies, executes every selected test separately and rejects a
missing, skipped, duplicate, failed or timed-out test. Go runs with the race detector.

A runtime PASS closes the seven pinned implementation boundaries for these pinned private paths.
It does not establish external independent review, normative adoption, live registry
or host isolation, full 71-case coverage, or protocol conformance. Those statuses
remain `NOT_ESTABLISHED` or `NOT_RUN` until their own evidence exists.

On 2026-09-23, the source audit verified both pinned checkouts. The runtime adapter
built both archived sources and passed 24 of 24 selected tests in each core, including
all thirteen owner-admission tests per core. The related Inspector controls and full Go
test suite also passed. CI regenerates and preserves these reports rather than
treating this local observation as immutable release evidence.
