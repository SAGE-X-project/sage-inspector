# Adopted MCP binding evidence

The combined checker binds five evidence sets without collapsing their meanings:

| Evidence set | Checked result |
|---|---:|
| Historical proposal catalog | 71 `NOT_RUN` preserved |
| Current parent-case overlay | 71 PASS |
| Mandatory child schedules | 26 PASS in Go and 26 PASS in Rust |
| Protected native pairs | 4 PASS |
| Completed-journal restart observations | 8 PASS |

`check_mcp_binding_evidence.py` verifies that the parent overlay hashes the same core
runtime report, every mandatory child is attached to an exact passing core test and
hashed log, and the Go/Go, Go/Rust, Rust/Go and Rust/Rust protected runs preserve raw
frames, signed exchanges, `RESERVED` → `EXECUTING` → `COMPLETED` transitions, one
terminal record and the expected inert effect. It also checks server and client reopen
observations for every pair, zero new effects and unchanged completed journals.

```sh
python3 -B scripts/test_mcp_binding_evidence.py
python3 -B scripts/check_mcp_binding_evidence.py \
  --runtime /path/to/mcp-core-runtime \
  --parents /path/to/mcp-case-evidence \
  --interop /path/to/mcp-native-protected \
  --output /tmp/new-mcp-binding-evidence
```

The report pins the adopted spec revision and normative baseline hash. It uses
`EVIDENCE_CHECKED` and retains `conformance: NOT_ESTABLISHED`.
Implementation assertions and selected interoperability observations do not by
themselves establish complete protocol conformance or external review.
