# MCP proposal case evidence

The consolidated proposal snapshot remains an immutable historical catalog of 71
`NOT_RUN` cases. Inspector derives a separate current overlay from pinned core
runtime, native interoperability and policy evidence without editing that snapshot
or treating the proposal as adopted normative text.

The aggregate overlay combines two contracts:

| Contract | Case set | Current result |
|---|---|---:|
| Resolution evidence | 13 `mres-*` cases | 13 PASS |
| [MSET evidence](mcp-setup-case-evidence.md) | 40 original `mset-*` and 18 addendum `madd-*` cases | 58 PASS |
| Aggregate | All catalog identities | 71 PASS |

The thirteen resolution cases cover admission and close order, crash recovery,
protected deadlines, READY lifetime, intent/result/carriage algorithm boundaries,
missing signing keys, stale setup completion and close before reservation. Their
exact Go and Rust tests remain listed in the machine-readable
[case contract](../verification/0.10.0/mcp-case-evidence-contract.json).

The remaining 58 cases require the separate
[MSET contract](../verification/0.10.0/mcp-setup-case-contract.json). Fifty-three
bind exact tests in both cores, two bind the full protected interoperability and
restart matrix, and three bind explicit policy statements in the hashed consolidated
proposal. The aggregate checker accepts their result only from a complete MSET report
whose contract and runtime report hashes match.

```sh
python3 -B scripts/test_mcp_case_evidence.py
python3 -B scripts/check_mcp_case_evidence.py \
  --runtime /path/to/mcp-core-runtime \
  --setup /path/to/mcp-setup-case-evidence \
  --output /tmp/new-mcp-case-evidence
```

The report contains all 71 case IDs and `71 PASS / 0 PARTIAL / 0 NOT_RUN` in
`runtime_case_counts`. Its `historical_catalog` remains `{ "NOT_RUN": 71 }`, so a
consumer cannot confuse the original planning state with the derived evidence.
`EVIDENCE_CHECKED` is an evidence-integrity result rather than an aggregate protocol
PASS.

The overlay uses controlled clocks, temporary journals, inert effect counters and
bounded local scheduling seams. It executes no external target and contains no
attack reproduction. PASS means that the contract's selected observation was present
in the pinned implementations, interoperability run or proposal text. External
review remains `NOT_PERFORMED`, adoption remains `PROPOSAL_NOT_ADOPTED`, and full
protocol conformance remains `NOT_ESTABLISHED`.
