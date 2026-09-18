# Guard signed result publication

The Go and Rust DispatchGate APIs now connect accepted execution tokens, one local
response permit per invocation, and durable first signed terminal envelopes. This
report concerns the 0.10.0 Ed25519 Guard subset. It does not establish client terminal
consumption, MCP mapping, deployed authority, immutable host loading or isolation.
The existing 37 lifecycle scenarios remain NOT_RUN; conformance is NOT_ESTABLISHED.

## Verified behavior

- Finish persists COMPLETED plus its signed bytes before any Reply can publish it.
  It does not itself send a response. An accepted worker retains a gate-bound token.
- Reply consumes the receipt once, including on failure. Pending cannot be followed
  by terminal on that same invocation. A fresh Dispatch authenticates each retrieval.
- Stored completed, rejected and unknown results are reused byte for byte. Revoked
  keys, unavailable authority and expired result envelopes deny without re-signing.
- Accepted responses can outlive intent expiry; a new retrieval cannot. The result's
  independent validity interval still applies. The publisher uses a 300-second TTL.
- Recovery turns unfinished execution into UNKNOWN. A returning signer can persist
  the first signed unknown, which is immutable on subsequent opens.
- Explicit rejection atomically reserves an absent call and nonce. It verifies the
  incoming intent and policy first and cannot overwrite a running call.
- Native tests additionally cover concurrent Finish/Reply, malformed outputs, foreign
  tokens, proof failures, storage capacity and expiry during the final storage check.

## Independent runtime evidence

`adapters/go/cmd/sage-guard-results010` and Rust `guard_results010` invoke only real
core APIs. Their sink verifies owned public artifact bytes and records the accepted
invocation, without invoking a shell, network or external tool. Trusted fixture clock,
key availability and policy controls do not represent a production trust source.
Inputs are bounded to 64 JSONL commands, each at most 4 MiB, in a timed local process.
The deterministic executor key is explicitly public fixture material.

`test_guard_results010.py` runs 16 scenarios and 12 recovery combinations, using
44 actual processes. Each of Go->Go, Go->Rust, Rust->Go and Rust->Rust covers completed,
rejected and unknown recovery; signed UNKNOWN is opened a second time. It checks
exact effects, state transitions, signature counts, receipt failures and journal
identity. Command input, exit/stdout/stderr and before/after journals are retained
with hashes, core revisions, adapter hashes and fixture hash in a fresh directory.

`check_guard_results010.js` independently constructs the expected closed result
body and checks its Ed25519 proof with Node/OpenSSL, not either target core. The
oracle is scoped to these bounded public fixture values, not a general-purpose JCS
implementation. It verifies 102 published or stored envelopes. Offline evidence
mutation tests ensure missing responses, changed counters, missing terminal bytes,
incorrect bindings and invalid proofs cannot produce a passing report.

CI stores this as a separate `guard-result-bindings` artifact. Historical evidence,
the primitive suite and previous dispatch/reservation artifacts retain their own
meaning; these results are not promoted into full lifecycle certification.

## Reproduction

Build the two result adapters against the revisions in `test_record010_adapters.py`.
Run `python3 scripts/test_guard_result_reports.py`, then:

```sh
python3 scripts/test_guard_results010.py --go /path/to/sage-guard-results010 \
  --rust /path/to/guard_results010 --output /new/evidence/directory
```

`--development` permits unpinned checkouts and labels the report accordingly; it is
not used for CI or the final pinned verification. Failed runs preserve raw evidence.

Next is the client-side single terminal consumption and polling contract, followed
by MCP result mapping. Production transport must bind each receipt to exactly one
outer invocation; a host that deliberately calls Dispatch twice for one outer request
violates that contract. Registry deployment and host enforcement remain dependencies.
