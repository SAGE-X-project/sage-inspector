# External native MCP consumer fixtures

These separate Go modules and Rust executables import public core APIs only.
They capture one fixed original request, approve and issue it once, obtain a
read-only signed snapshot, close the issuer Client and reopen the same protected
journal inside the native MCP connection with `create=false`. The owner checks
current policy, capture and registry authority again before any handoff.

The server measures the same loaded inert fixture instance used by its exact
`read({"path":"public.txt"})` executor. It increments a counter and returns
`{"ok":true}`; it does not read arbitrary files, run commands or load plugins.
The marker and journals are observed after owner shutdown. The fixture signer
checks the durable issuance fence before signing. Inspector independently
verifies the signed intent/result, approved commitments, journal continuity,
reservation/execution/completion ledger and measured effect count.

`scripts/inspect_mcp_consumer.py` builds pinned separate consumers with locked
cached dependencies and starts only loopback TCP processes. Four allowed
directions and five denials in each cross-core direction are required. Denials
cover policy, loaded measurement, independently captured original, responder
readiness and signing failure. The report also records where each denial
occurred so a failed handshake cannot stand in for policy or measurement checks.

All seeds are deterministic public fixtures. Registry readiness and finality are
local assertions, not a deployed registry observation. Logical time advances
through the real replay provider's 360-second startup quarantine; wall-clock
waiting for that period is not tested. The inert loaded instance is not a
production plugin loader, isolated signer or immutable executable measurement.
The server consumes one root request; independent hop execution, outer handshake
oracle, deployed host and full conformance remain open.
