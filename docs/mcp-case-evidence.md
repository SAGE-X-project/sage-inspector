# MCP proposal case runtime evidence

The consolidated proposal snapshot remains an immutable historical catalog of 71
`NOT_RUN` cases. This evidence overlay derives a separate current result from actual
private-core runtime tests without editing that snapshot or treating the proposal as
adopted normative text.

The current assessment is intentionally narrow:

| Case | Go evidence | Rust evidence | Result |
|---|---|---|---|
| `mres-close-after-reservation` | `TestMCPAdmissionCloseDuringFence` | `close_during_post_fence_callback_denies_and_retains_history` | PASS |
| `mres-close-after-admission` | close after insertion plus authenticated duplicate | admitted worker plus duplicate | PASS |

The first case observes closure after reservation and durable EXECUTING storage but
before final owner admission. Both cores deny the effect, retain conservative durable
state and check retained request-ID history. Go also compares the exact stored nonce
with the authenticated intent across successful, failed and uncertain persistence
outcomes. The second case observes closure after committed admission. Its Go mapping
also requires the authenticated duplicate test; both cores retain the outcome and
prevent duplicate execution instead of claiming rollback.

All five tests use controlled clocks, temporary journals, inert effect counters and
bounded local scheduling seams. They do not invoke an external target or implement
an attack. Go executes under the race detector in the runtime adapter.

## Evidence derivation

The [case contract](../verification/0.10.0/mcp-case-evidence-contract.json) binds the
historical catalog manifest, owner-admission contract, two exact case IDs and their
required tests across both cores. The checker requires a complete passing 26-test
runtime report, both pinned core revisions, the preserved owner contract, the preserved
runner hash, exact mapped test rows, hashed logs and one observed passing invocation
per required test. Missing, duplicated, skipped, changed or merely relabelled logs
fail the derivation.

```sh
python3 -B scripts/test_mcp_case_evidence.py
python3 -B scripts/check_mcp_case_evidence.py \
  --runtime /path/to/mcp-core-runtime \
  --output /tmp/new-mcp-case-evidence
```

The report contains all 71 case IDs. Two carry current `PASS` evidence and 69 remain
`NOT_RUN`. The historical catalog field remains `{ "NOT_RUN": 71 }` so a consumer
cannot confuse source-plan status with current runtime evidence. CI creates
the overlay only after the pinned runtime runner succeeds and preserves both reports
in the same native MCP artifact.

The aggregate report status is `EVIDENCE_CHECKED`; it is not an aggregate protocol
PASS. Individual case status must be read from `runtime_case_counts` and `cases`.

`PASS` here means that the complete resolution-plan scenario ran through the pinned
private implementations with its stated unit and bounded-runtime assertions. It does
not establish independent external review, normative adoption, public API
compatibility, live registry or host isolation, any of the other 69 cases, or full
protocol conformance. Crash-after-admission, deadline and signature cases remain
`NOT_RUN` until their exact inputs and required observations are present in both cores.
