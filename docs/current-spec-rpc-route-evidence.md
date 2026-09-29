# Current-spec guarded RPC route observations

The [two public request fixtures](../vectors/0.10.0/exec-rpc-routes.json)
compare a valid `sage_secure_call` against a notification and a direct tool
call. The independent checker pins the exact request bytes and confirms the
excluded route shape. Separate local ledger runs prevent the positive control
from affecting either candidate.

Pinned Go and Rust cores accept the control and make one inert dispatch. Both
reject the notification and direct tool call without a ledger reservation or
dispatch. The [revision-bound observations](evidence/current-spec/exec-rpc-routes/)
are `PARTIAL`; reassess with
`python3 -B scripts/check_current_spec_rpc_route_evidence.py`.
These bounded RPC entry points do not prove that every deployed host path
routes protected tool calls through them or that the LLM hook cannot bypass
the boundary.
