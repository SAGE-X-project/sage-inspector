# Adopted A2A and DID inspection

The separate adopted inventory pins sage-spec
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`: 45 requirements, 104 rule groups,
583 parent cases and 26 mandatory subscenarios. It adds 64 A2AB cases,
28 DIDP cases and two TABLE-08 cases to the frozen 489-case inventory.
No previous case object is removed or changed. Existing observations retain
their own specification revision; matching case objects do not transfer PASS
between changed normative sources.

`scripts/a2a_did_catalog.py` checks the complete requirement/rule/case graph,
source hashes, exact adopted manifest and preservation of the frozen cases.
It reports all cases as NOT_RUN, never implementation conformance.

## Card library observations

The independent input file contains 41 signed or deliberately invalid card
fixtures. Card bytes and expected decisions were prepared outside the ADK with
Python cryptography and direct canonical JSON for an ASCII-key, integer-only
subset of JCS. Ed25519 uses a published zero test seed; P-256 uses published
test scalar one and nonce seven with mathematical raw low-S construction.
They are public test values, never custody or deployment credentials. The offline
construction source is preserved in
`verification/0.10.0/a2a-did/fixture-construction.py.txt`; it is not run by the observer.

The fixtures exercise extension shape/version/lifetime, card structure and
bounds, exact JWS headers and key roles, Ed25519/P-256 signature acceptance,
key revocation, record version and card expiry, protobuf default/presence,
and byte-exact service/interface matching. The ordinary repeated-default
fixture uses the real AgentSkill `examples` field. The adopted case's example
of `extensions` on a skill is not a field in the pinned A2A model; it must not
be added to that model. This fixture observes the default-normalization rule
and remains partial; the wording discrepancy is retained for later spec review.

`adapters/a2a-card` calls the public ADK verifier pinned to `904fa9c`.
Its Source and clock are clearly marked local fixtures. It performs no network
request, Registry proof/readiness acquisition, protected envelope delivery,
application effect, vulnerability reproduction or host bypass.

`scripts/a2a_card_observation.py --native` verifies the public module versions
and cache, rejects module replacements and unexpected compiler inputs, builds
the adapter, and launches a distinct bounded native process for every fixture.
It stores the compiler version and exact input, executable, module and observer source hashes,
raw process output and the typed comparison with the independent expectation.
A synthetic admission test is not a native process observation.

Matching outputs produce **PARTIAL** for 41 parent cases; mismatches produce
**FAIL**. The other 542 cases remain **NOT_RUN** at this revision. The report
cannot accept self-reported PASS, duplicate/unknown case IDs, wrong input hashes,
uninspected output members or integers masquerading as booleans. Full
conformance remains **NOT_ESTABLISHED** even if every card comparison matches.
The transport and deployed Registry remain NOT_RUN and NOT_BOUND respectively.

```sh
python3 -B scripts/a2a_did_catalog.py --spec-root /path/to/pinned/sage-spec \
  --output /tmp/a2a-did-inventory.json
(cd adapters/a2a-card && GOTOOLCHAIN=local go mod download && \
  go test -mod=readonly -race -coverprofile=/tmp/a2a-card.cover ./...)
python3 -B scripts/a2a_card_observation.py --native \
  --output /tmp/a2a-card-native.json
```

Use Go 1.26.8. The native observer builds with GOWORK off, readonly modules,
CGO disabled and GOPROXY off after the pinned dependencies are downloaded.
The separate A2A/DID CI retains raw observations and checks the new Go adapter's
statement coverage and each new Python inspection file’s executed statement-line
coverage at 90% or above. These are not branch-coverage claims. These fixtures do not replace the existing
historical observation workflows or general Inspector tests.

## Remaining work in the approved order

The Inspector extension is still in progress. Next are the remaining 23 A2AB
request/response-policy and transport cases, 28 DIDP projection/resolution cases,
and two TABLE-08 cases. Bind independent expectations to actual ADK/Go/Rust
subjects and inspect advanced/sage separately with did-inspector's DID Core 1.0
and DID 1.1 profiles. HTTP/envelope/replay evidence requires a real supporting
adapter and must remain unsupported or not run until it exists. A local library
fixture cannot establish that a deployed endpoint forbids alternate transports.

The production A2A TransportOwner/core metadata integration and actual eip155
RPC/ABI/contract Source remain in the planned core/contract migration. This
Inspector change does not revise the normative spec or move those decisions.
W3C publication, broader DID case coverage, demo, facilitator, discovery and
later chain work retain the original sequence.
