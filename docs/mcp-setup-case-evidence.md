# Authenticated MCP setup case evidence

The MSET evidence contract covers all 58 original and addendum cases in the
consolidated non-HTTP MCP proposal. It preserves the historical catalog as 71
`NOT_RUN` entries and derives a separate current overlay from pinned implementation,
interoperability and policy evidence.

Evidence is divided by what each case asserts:

| Evidence class | Cases | Required observation |
|---|---:|---|
| Core runtime | 53 | One exact passing Go test and one exact passing Rust test, with pinned source hashes, preserved logs and explicit case mappings |
| Native interoperability | 2 | Go/Go, Go/Rust, Rust/Go and Rust/Rust protected exchanges plus server and client journal reopening for every pair |
| Policy assertion | 3 | Explicit proposal status, excluded HTTP behavior and unchanged historical catalog state in the hashed consolidated proposal |

The core runner executes 64 selected Go tests and 61 selected Rust tests. Within
that inventory, 32 Go tests and 28 Rust tests jointly provide 53 case links per
language. A test may support several cases only when the contract lists each link;
the checker rejects missing, duplicate, skipped, changed or merely relabelled rows.

The native runner requires the setup frames plus one or two protected exchanges,
with 10 or 12 frames and 13 or 15 independently verified signatures. It also checks
one effect, one terminal record, exact durable transitions and independently opened
encrypted records. Recovery evidence is an exact 2 by 4 matrix: both server
and client reopening modes must pass for every language pair. Each recovery row now
records its mode, so eight successful rows with a duplicated mode cannot satisfy the
contract.

MSET-08 policy results are narrow assertions rather than runtime claims. The checker
requires the consolidated proposal to remain `PROPOSAL_NOT_ADOPTED`, requires its
MSET-08 section to state that chapter 08 HTTP behavior is not defined, and requires
the historical catalog to remain `{ "NOT_RUN": 71 }`.

```sh
python3 -B scripts/test_mcp_setup_cases.py
python3 -B scripts/check_mcp_setup_cases.py \
  --runtime /path/to/mcp-core-runtime \
  --interop /path/to/mcp-native-protected-restart \
  --output /tmp/new-mcp-setup-case-evidence
```

A successful report contains `58 PASS / 0 PARTIAL / 0 NOT_RUN`. This means each
proposal case has the selected evidence required by the contract. It does not adopt
the proposal, replace external review, define the excluded HTTP behavior or establish
full protocol conformance. Those fields remain `PROPOSAL_NOT_ADOPTED`,
`NOT_PERFORMED` and `NOT_ESTABLISHED`.
