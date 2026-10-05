# Captured Client signed result parity

The [machine-readable report](captured-client-results.json) records ten bounded public-API executions against the pinned Go and Rust cores. Inspector derives a valid signed root intent from its public fixture and independent original-byte vector, then independently signs executor results with the fixture Ed25519 key. A separate Node/OpenSSL oracle verifies the normal pending and completed result signatures and exact request binding. The test key is public and has no deployment authority.

Both cores release the exact completed output once, reject duplicate consumption, keep a pending result nonterminal, and reject a correctly signed result bound to a different intent digest as well as an invalid proof. The rejected results create no terminal journal event and release no output. The cores write identical journal bytes for each case. Each core can reopen the other's terminal journal and reject resubmission without another send or output release.

These observations cover captured Client result consumption and durable state at the public core API. The adapters use inert trusted services, not a deployed Agent/MCP host. They do not establish host-side pre-model capture, control of every effect and output route, production key custody, or complete 0.10.0 protocol conformance. The 13 host-port controls remain `NOT_RUN`.
