# Current-spec session identity and bound tuple

SESSION-01 derives a public 22-character session ID from the authenticated
handshake transcript hash. The ID differs from the handshake's UUID handle
and cannot authorize an action. A session retains its authenticated tuple,
selected key bytes and algorithms, and local role. Every incoming record
must match sender role, DID, recipient, signing key, context, version,
session ID, and selected key status before acceptance.

Eight revision-bound fixtures cover the four parent cases and all four
mandatory tuple subscenarios. An independent calculation checks the ID from
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
