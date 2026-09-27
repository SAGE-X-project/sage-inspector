# Current-spec session identity and bound tuple

SESSION-01 derives a public 22-character session ID from the authenticated
handshake transcript hash. The ID differs from the handshake's UUID handle
and cannot authorize an action. A session retains its authenticated tuple,
selected key bytes and algorithms, and local role. Every incoming record
must match sender role, DID, recipient, signing key, context, version,
session ID, and selected key status before acceptance.

Eight revision-bound fixtures cover the four SESSION-01 cases and four
related CST-04 tuple cases. An independent calculation checks the ID from
the source transcript. The positive fixture invokes each core's actual
0.10.0 record export through a bounded bridge in both directions and projects
the session IDs. The negative fixtures tie direct-secret, wrong-transcript,
role, DID, active-alternative-key, recipient/context/session-ID, and
selected-versus-unrelated registry changes to independently audited state
scenarios. A positive record ID observation cannot establish that the core
enforces these receiving and registry checks.

The current primitive adapters do not expose a stateful tuple verifier,
registry recheck, or protected-dispatch counters. Those denial fixtures must
remain `UNSUPPORTED` until an instrumented version-matched receiver adapter
can observe the full boundary. The independent session audit verifies
scenario expectations, not core behavior.

The [preserved 89-case Go/Rust run](evidence/current-spec/session01/) pins
`sage-spec` revision `5bcf511e604579afa63f434013447f44b6858828`, Go
`49379baadc6baec9ca8b4bb7d15bf43d65144bd7`, Rust
`ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396`, and Inspector runner
`0fe942b3be014b4583a303173f0cf59a8006d212`. Recheck source relations,
runner hashes, observations, and assessments with
`python3 -B scripts/check_current_spec_session01_evidence.py`.

Both cores return the expected SID for c2s and s2c, so SESSION-01-P is
`PARTIAL`. The remaining seven cases are `UNSUPPORTED`. Across all 481
cases, Go has 11 `FAIL`, 55 `UNSUPPORTED`, 23 `PARTIAL`, and 392 `NOT_RUN`;
Rust has five `FAIL`, 54 `UNSUPPORTED`, 30 `PARTIAL`, and 392 `NOT_RUN`.
Overall conformance is `NOT_ESTABLISHED`.
