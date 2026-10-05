# Captured Client public API parity

The [machine-readable report](captured-client-parity.json) records 12 bounded executions against the public Go and Rust core APIs at pinned source revisions. Inspector reconstructs a valid Ed25519-signed root intent from its existing public fixture, replaces its original-byte commitment with the independently checked `single-utf8` capture vector, and verifies the signature before execution. The fixture key is public test material only.

Both cores reject a changed original input or request ID before creating a journal. A matching capture opens the signed Client, records one send, and produces identical journal bytes. Reopening with a changed capture leaves the journal untouched. Reopening with the same capture does not send the unresolved invocation again. Inspector also opens each core's journal with the other core and checks the same no-duplicate-send result.

The adapter uses inert trusted-service fixtures and does not run in an agent host. The report establishes captured Client API behavior and cross-language durable-state parity only. Host capture timing, protected storage, production transport, signed result processing, and full protocol conformance remain outside this report; existing Guard Client evidence covers signed result processing separately.
