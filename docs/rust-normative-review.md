# Rust normative implementation review — SAGE 0.10.0

Rust revision `40b5a8c6d76d952131013d8a034f819fd31b7ca0` has direct implementation
assertions for all 26 mandatory child schedules adopted by `sage-spec` revision
`520e5ed9a896ff8ba8ade776484f41084957aaa2`.

| Classification | Count |
|---|---:|
| DIRECT | 26 |
| PARTIAL | 0 |
| MISSING | 0 |

The exact schedules cover independent policy, component and session generations,
observation boundaries, final capacity and insertion failures, shared owners, all
durable-fence outcomes, recovery conversion, expiry order, retirement and replacement
races, scheduler cancellation and retained capacity, reconnect cleanup, and the two
1024-record limits. The tests use controlled state and inert effects.

The [Rust review contract](../verification/0.10.0/rust-normative-review-contract.json)
maps each child ID to a fully qualified Rust test. The static checker verifies the
adopted spec inventory, revisions and test definitions. The core runtime runner then
executes each distinct test from the pinned source archive and preserves the selected
log, executable hash and dependency lock.

```sh
python3 -B scripts/test_rust_normative_review.py
python3 -B scripts/check_rust_normative_review.py \
  --spec-root /path/to/sage-spec --rust-root /path/to/rs-sage-core \
  --output /tmp/new-rust-normative-review
```

The result is implementation evidence for the mandatory schedules. Full protocol
conformance and external review remain `NOT_ESTABLISHED`.
