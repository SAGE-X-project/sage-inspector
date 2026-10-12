# A2A request and response policy observations

All 23 A2AB cases not covered by the independent card observations now have
explicit inspection contracts at sage-spec `06b50e1`. The observer is pinned
to the public ADK `904fa9c` and Go 1.26.8. It changes no normative specification,
core or ADK API, and does not implement the planned production transport owner.

Twenty contracts execute the actual ADK Client/Server policy API with an inert
handler and fixture Source/clock/owner. Three require production public ingress
or alternate-binding listeners; these have no available inspection adapter and
remain **UNSUPPORTED**, never a simulated rejection or a subject vulnerability.

The executable cases inspect exact JSON-RPC payload/reply bytes, version and
extension metadata, streaming rejection, recipient/tenant routing, trusted-owner
response Sender, terminal client failure and handler dispatch counts. The
uniform-error scenario compares two different ADK refusals. Counter names refer
to fixture handler/owner calls, not authorized application effects or transactions.

## Safe runtime and independent expectations

Each case runs directly in unit tests and through owned loopback TLS. The test
frame is explicitly marked `fixture-policy-only`; it is not a chapter 08 envelope.
The logical registered URI maps locally to the owned test server. The certificate
protects the fixture connection, not the card's public hostname or a deployed
SAGE peer. No chapter 03/08 signatures, durable replay or Execution Guard is
implemented by this harness.

The final client callback is invoked after TLS setup and before HTTP body
publication. A denied callback has a zero-publication control. TLS/network/frame
failures cause the observer to fail, rather than passing as expected policy
refusals. Invalid fixture frames never reach the ADK handler. No unsupported
bare HTTP, gRPC or legacy downgrade case is sent to a real endpoint. This is
scenario-based defensive verification, not vulnerability reproduction or bypass.

Inputs and expected outputs were prepared independently of the ADK result.
The tenant card was signed offline with the published zero test seed. Expected
JSON-RPC replies/errors, bytes and counters are stored in
`vectors/0.10.0/a2a-call-observations.json`; the offline construction source is
preserved separately as text. The fixture file is hash-pinned. Runtime reports
compare closed typed actual outputs; bools cannot stand in for counters, and
unknown/duplicate IDs, changed hashes and self-reported PASS are rejected.

The native runner validates module versions/sums and cache, rebuilds the adapter,
launches a bounded process for each policy case, and records raw outputs, input
and executable hashes, compiler version and observer/adapter source hashes.
Compiler input lists and file hashes are checked both before and after execution,
including newly added build sources. The existing card launcher shares this
strengthened input check. No previous historical evidence is rewritten.

## Results and limits

Matching policy cases are **PARTIAL**, mismatches are **FAIL**. The three public
ingress contracts are unsupported by this observer. Running fresh card and call
observations together yields 61 PARTIAL, three UNSUPPORTED and 519 NOT_RUN in the
583-case inventory. Full conformance stays NOT_ESTABLISHED; signed carriage stays
NOT_RUN and the deployed Registry stays NOT_BOUND.

Each contract and result records its unobserved portions. In particular:

- Header hints are ignored by the fixture and the ADK receives metadata only;
  production signed-envelope/header processing is not established.
- An A2A JSON-RPC error survives the client/server API as response bytes with no
  library error. The chapter 08 outer `success` field is not observed.
- The wrong-signer case checks a mismatching Sender in a trusted-owner response;
  it does not verify an actual response signature or its signing key.
- Retry cases observe rejection of a request carrying unchanged `1.0` because
  the fresh fixture Source fails, followed by no second owner invocation. They
  do not prove version-negotiation-specific refusal or protection of alternate
  deployed listeners.

```sh
(cd adapters/a2a-call && GOTOOLCHAIN=local go mod download && \
  go test -mod=readonly -race -coverprofile=/tmp/a2a-call.cover ./...)
python3 -B scripts/test_a2a_call_observation.py
python3 -B scripts/a2a_call_observation.py --native --include-cards \
  --output /tmp/a2a-call-native.json
```

Download both observer modules before the combined run. The native runner uses
readonly, offline modules, GOWORK off and CGO disabled. CI checks independent
contracts, direct/TLS unit tests, native processes, module integrity and at least
90% Go statement and Python executed-statement-line coverage. No branch-coverage
or organizational external-audit claim is made.

The requested 23 inspection connections are prepared, with explicit missing
production observers. Remaining work in the same approved Inspector extension
is DIDP 28, TABLE-08 two and the separate advanced/sage subject in did-inspector.
Production A2A transport/core metadata and actual eip155 Source stay in the
planned core/contract migration and require subsequent inspection.
