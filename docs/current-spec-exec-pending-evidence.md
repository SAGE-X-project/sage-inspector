# Current-spec pending and UNKNOWN observations

The [two case fixtures](../vectors/0.10.0/exec-pending.json) distinguish an
ordinary signed `pending` result from a signed `unknown` terminal result at
the Client API. After `unknown`, the Client refuses a new handoff. A separate
MCP primitive checks that signed `pending` projects to `isError: true`,
`status: pending`, and matching text and structured representations. The
independent vector check verifies the signatures and the exact intent digest.

The [archived Go and Rust observations](evidence/current-spec/exec-pending/)
are `PARTIAL` for both cases. Client recovery that receives a stored UNKNOWN
after restart, the HTTP pending mapping, and deployed model consumption are
not covered. Reassess the archive with
`python3 -B scripts/check_current_spec_exec_pending_evidence.py`.
