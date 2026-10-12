# Exact A2A registry service-type observations

This observer connects the two TABLE-08 cases in adopted specification
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`. It exercises the actual card verifier
in sage-adk `904fa9cbe3c4c2dcdabee67b2afd7c9e4b75cf14` through two separate,
bounded native processes. Both matched cases are PARTIAL, never full conformance.

The independent fixture reuses the already reviewed and pinned signed card
`a2ab-03-declared`. Card bytes, public key, clock, record lifecycle and URI are
identical in both cases. Only the fixture record's service type changes:

| Case | Registry service type | Expected library result |
|---|---|---|
| `TABLE-08-P` | `A2AInterface` | Accepted; the exact card interface URI is eligible |
| `TABLE-08-N01` | `a2ainterface` | Rejected with the generic authentication failure; no eligible interface |

The positive control proves that this identical card is accepted with the
correct type, including the verifier's card and signature checks. Without that
matched control, a negative generic refusal cannot isolate a service-type cause;
the observer leaves that negative case NOT_RUN. A mismatching negative result
remains FAIL. Unit controls also exercise other unlisted type spellings and
mismatched adapter type counts. No case attempts to contact an external agent.

The adapter's optional `service_types` fixture input selects the types explicitly.
Absent or empty type lists keep the previous `A2AInterface` default for the
existing 41 card cases; nonempty lists must match the service URL count. No
subject library, registry implementation or normative specification changes.

The fixture Source and clock are explicit local test data. They do not establish
registry proofs, freshness, deployed identity, protected transmission, replay
checks or host assurance. The report records these boundaries and preserves raw
stdout, input hashes, compiler and module identities, source hashes and the
executable hash. Compiler inputs, module cache and observer sources are checked
before and after execution. The fixture construction script is preserved beside
the adopted inventory; it verifies the prior independent fixture hash before
constructing this pair and does not query the implementation for expected values.

## Reports and commands

```sh
python3 -B scripts/a2a_service_type_observation.py --native --output /tmp/a2a-service-types.json
python3 -B scripts/a2a_service_type_observation.py --native --include-a2a --output /tmp/a2a-services-combined.json
```

The first command observes only these two cases: two PARTIAL and 581 NOT_RUN.
The second freshly executes the existing 41 card and 20 request policy cases as
well: 63 PARTIAL, three production-ingress UNSUPPORTED and 517 NOT_RUN. All
components have the same pinned ADK subject and adopted spec revision. Overlaps,
subject drift, incomplete inventory and whole-case PASS transfer are rejected.
Synthetic reported outputs remain distinct from Inspector-launched execution.

The DID projection/resolution report is a different did-go subject and remains
separate: 23 PARTIAL, two FAIL, three UNSUPPORTED and 555 NOT_RUN. Its two missing
metadata members are not resolved or promoted by these service-type results.
Frozen historical reports are not relabeled for the adopted specification.

All 94 added adopted inventory cases now have an observation contract, including
explicit unsupported boundaries. This is not completion of the wider inspection
work or of deployed protocol conformance. Next is did-inspector's independent
advanced/sage subject coverage and separate DID Core 1.0/DID 1.1 judgments.
Production A2A ingress and transport, actual eip155 registry connection, and the
two DID implementation findings remain in the approved core migration work.
